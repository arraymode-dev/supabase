


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE EXTENSION IF NOT EXISTS "pgsodium";






COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE EXTENSION IF NOT EXISTS "hypopg" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "index_advisor" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pg_graphql" WITH SCHEMA "graphql";






CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgjwt" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";






CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";






CREATE OR REPLACE FUNCTION "public"."anomaly_summary"("scope" "jsonb") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
declare result jsonb;
begin

  select jsonb_build_object(
    'max_risk', max(rop.combined_risk_score),
    'min_risk', min(rop.combined_risk_score),
    'stddev_risk', stddev(rop.combined_risk_score)
  )
  into result
  from risk_object_property rop
  join risk_object ro
    on ro.risk_object_id = rop.risk_object_id
  where (scope->>'portfolio') is null
     or ro.portfolio_name = scope->>'portfolio';

  return result;

end;
$$;


ALTER FUNCTION "public"."anomaly_summary"("scope" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cleanup_expired_locks"() RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  DELETE FROM cell_locks WHERE expires_at < NOW();
END;
$$;


ALTER FUNCTION "public"."cleanup_expired_locks"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."execute_dynamic_query"("query_text" "text") RETURNS "json"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  result JSON;
  cleaned_query TEXT;
BEGIN
  -- Trim whitespace and clean the query
  cleaned_query := TRIM(BOTH FROM query_text);
  
  -- Allow SELECT queries and WITH clauses (CTEs) for security
  -- WITH clauses are safe read-only queries that can precede SELECT
  IF NOT (cleaned_query ~* '^\s*(SELECT|WITH)') THEN
    RAISE EXCEPTION 'Only SELECT queries are allowed';
  END IF;
  
  -- Prevent potentially dangerous operations (case-insensitive)
  IF cleaned_query ~* '\b(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE|GRANT|REVOKE)\b' THEN
    RAISE EXCEPTION 'Query contains prohibited operations';
  END IF;
  
  -- Execute the query and return results as JSON
  EXECUTE format('SELECT COALESCE(json_agg(row_to_json(t)), ''[]''::json) FROM (%s) t', cleaned_query) INTO result;
  RETURN result;
EXCEPTION
  WHEN OTHERS THEN
    RETURN json_build_object('error', SQLERRM);
END;
$$;


ALTER FUNCTION "public"."execute_dynamic_query"("query_text" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_location_snapshot_count"("p_location_id" "text") RETURNS integer
    LANGUAGE "sql" STABLE
    AS $$
  SELECT COUNT(*)::INTEGER FROM location_snapshot
  WHERE location_id = p_location_id;
$$;


ALTER FUNCTION "public"."get_location_snapshot_count"("p_location_id" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_portfolio_counts"() RETURNS TABLE("name" "text", "count" bigint)
    LANGUAGE "sql" STABLE
    AS $$
  SELECT 
    portfolio_name as name,
    COUNT(*) as count
  FROM risk_object
  WHERE portfolio_name IS NOT NULL
  GROUP BY portfolio_name
  ORDER BY portfolio_name;
$$;


ALTER FUNCTION "public"."get_portfolio_counts"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."outlier_list"("scope" "jsonb") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
declare threshold numeric;
declare result jsonb;
begin

  select avg(combined_risk_score) + 2 * stddev(combined_risk_score)
  into threshold
  from risk_object_property;

  select jsonb_agg(row_to_json(t))
  into result
  from (
    select rop.risk_object_property_id,
           rop.location_label,
           rop.combined_risk_score
    from risk_object_property rop
    join risk_object ro
      on ro.risk_object_id = rop.risk_object_id
    where rop.combined_risk_score > threshold
  ) t;

  return coalesce(result, '[]'::jsonb);

end;
$$;


ALTER FUNCTION "public"."outlier_list"("scope" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."random_between"("low" integer, "high" integer) RETURNS integer
    LANGUAGE "plpgsql"
    AS $$
BEGIN
   RETURN floor(random() * (high - low + 1) + low);
END;
$$;


ALTER FUNCTION "public"."random_between"("low" integer, "high" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."random_date"("start_date" "date", "end_date" "date") RETURNS "date"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
   RETURN start_date + (random() * (end_date - start_date))::INT;
END;
$$;


ALTER FUNCTION "public"."random_date"("start_date" "date", "end_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."random_decimal"("low" numeric, "high" numeric) RETURNS numeric
    LANGUAGE "plpgsql"
    AS $$
BEGIN
   RETURN low + (random() * (high - low));
END;
$$;


ALTER FUNCTION "public"."random_decimal"("low" numeric, "high" numeric) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."recommend_actions"("scope" "jsonb") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
begin
  return jsonb_build_object(
    'recommendations', jsonb_build_array(
      'Reduce exposure in high flood regions',
      'Review top 10 risk properties',
      'Diversify geographic concentration'
    )
  );
end;
$$;


ALTER FUNCTION "public"."recommend_actions"("scope" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."risk_band_distribution"("scope" "jsonb") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
declare result jsonb;
begin

  select jsonb_agg(row_to_json(t))
  into result
  from (
    select
      case
        when rop.combined_risk_score >= 8 then '8+'
        when rop.combined_risk_score >= 5 then '5-7'
        else '0-4'
      end as band,
      count(*) as count
    from risk_object_property rop
    join risk_object ro
      on ro.risk_object_id = rop.risk_object_id
    where (scope->>'portfolio') is null
       or ro.portfolio_name = scope->>'portfolio'
    group by band
  ) t;

  return coalesce(result, '[]'::jsonb);

end;
$$;


ALTER FUNCTION "public"."risk_band_distribution"("scope" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."risk_breakdown"("scope" "jsonb", "dimension" "text" DEFAULT 'country'::"text") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $_$
declare result jsonb;
begin

  if dimension not in ('country','city','construction_type','natural_catastrophe_zone') then
    raise exception 'Invalid dimension';
  end if;

  execute format(
    'select jsonb_agg(row_to_json(t)) from (
       select %I as dimension,
              avg(rop.combined_risk_score) as avg_risk,
              sum(rop.total_insured_value) as total_tiv
       from risk_object_property rop
       join risk_object ro
         on ro.risk_object_id = rop.risk_object_id
       where ($1->>''portfolio'') is null
          or ro.portfolio_name = $1->>''portfolio''
       group by %I
     ) t', dimension, dimension
  )
  into result
  using scope;

  return coalesce(result, '[]'::jsonb);

end;
$_$;


ALTER FUNCTION "public"."risk_breakdown"("scope" "jsonb", "dimension" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."risk_compare"("portfolio_a" "text", "portfolio_b" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
declare result jsonb;
begin

  select jsonb_build_object(
    'portfolio_a_avg', avg(combined_risk_score)
  )
  into result
  from risk_object_property rop
  join risk_object ro
    on ro.risk_object_id = rop.risk_object_id
  where ro.portfolio_name = portfolio_a;

  return result;

end;
$$;


ALTER FUNCTION "public"."risk_compare"("portfolio_a" "text", "portfolio_b" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."risk_drivers"("scope" "jsonb") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
declare result jsonb;
begin

  select jsonb_agg(row_to_json(t))
  into result
  from (
    select
      avg(rop.flood_risk_score) as avg_flood,
      avg(rop.earthquake_risk_score) as avg_earthquake,
      avg(rop.windstorm_risk_score) as avg_windstorm,
      avg(rop.fire_risk_score) as avg_fire
    from risk_object_property rop
    join risk_object ro
      on ro.risk_object_id = rop.risk_object_id
    where (scope->>'portfolio') is null
       or ro.portfolio_name = scope->>'portfolio'
  ) t;

  return coalesce(result, '[]'::jsonb);

end;
$$;


ALTER FUNCTION "public"."risk_drivers"("scope" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."risk_summary"("scope" "jsonb") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
declare result jsonb;
begin

  select jsonb_build_object(
    'location_count', count(*),
    'avg_combined_risk_score', avg(rop.combined_risk_score),
    'total_insured_value', sum(rop.total_insured_value),
    'annual_expected_loss_combined', sum(rop.annual_expected_loss_combined)
  )
  into result
  from risk_object_property rop
  join risk_object ro
    on ro.risk_object_id = rop.risk_object_id
  where (scope->>'portfolio') is null
     or ro.portfolio_name = scope->>'portfolio';

  return coalesce(result, '{}'::jsonb);

end;
$$;


ALTER FUNCTION "public"."risk_summary"("scope" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."risk_summary"("scope" "jsonb", "time_window" "text" DEFAULT '12m'::"text") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
declare
  result jsonb;
begin
  -- Example placeholder aggregation
  select jsonb_build_object(
    'total_locations', count(*),
    'avg_risk_score', avg(risk_score),
    'time_window', time_window
  )
  into result
  from properties
  where (scope->>'portfolio') is null
     or portfolio_id = scope->>'portfolio';

  return result;
end;
$$;


ALTER FUNCTION "public"."risk_summary"("scope" "jsonb", "time_window" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."risk_top_properties"("scope" "jsonb", "page_size" integer DEFAULT 10, "metric" "text" DEFAULT 'combined_risk_score'::"text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $_$
declare
  result jsonb;
begin

  -- Guard: metric must be provided
  if metric is null then
    raise exception 'Metric cannot be null';
  end if;

  -- Guard: allowlisted metrics only
  if metric not in (
    'combined_risk_score',
    'flood_risk_score',
    'earthquake_risk_score',
    'windstorm_risk_score',
    'fire_risk_score'
  ) then
    raise exception 'Invalid metric: %', metric;
  end if;

  -- Guard: page_size must be positive
  if page_size is null or page_size <= 0 then
    raise exception 'Invalid page_size';
  end if;

  execute format(
    '
    select jsonb_agg(row_to_json(t))
    from (
      select
        rop.risk_object_property_id,
        coalesce(rop.location_label, ro.name) as location_label,
        rop.%I as metric_value,
        coalesce(rop.total_insured_value, 0) as total_insured_value
      from public.risk_object_property rop
      join public.risk_object ro
        on ro.risk_object_id = rop.risk_object_id
      where
        rop.%I is not null
        and (
          ($1->>''portfolio'') is null
          or ro.portfolio_name = $1->>''portfolio''
        )
      order by rop.%I desc nulls last
      limit $2
    ) t
    ',
    metric,
    metric,
    metric
  )
  into result
  using scope, page_size;

  return coalesce(result, '[]'::jsonb);

end;
$_$;


ALTER FUNCTION "public"."risk_top_properties"("scope" "jsonb", "page_size" integer, "metric" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."risk_trend"("scope" "jsonb") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
declare result jsonb;
begin

  select jsonb_agg(row_to_json(t))
  into result
  from (
    select snapshot_date,
           average_risk_score,
           annual_expected_loss_combined
    from portfolio_snapshots
    where (scope->>'portfolio') is null
       or portfolio_name = scope->>'portfolio'
    order by snapshot_date
  ) t;

  return coalesce(result, '[]'::jsonb);

end;
$$;


ALTER FUNCTION "public"."risk_trend"("scope" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."rls_auto_enable"() RETURNS "event_trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog'
    AS $$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN
    SELECT *
    FROM pg_event_trigger_ddl_commands()
    WHERE command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
      AND object_type IN ('table','partitioned table')
  LOOP
     IF cmd.schema_name IS NOT NULL AND cmd.schema_name IN ('public') AND cmd.schema_name NOT IN ('pg_catalog','information_schema') AND cmd.schema_name NOT LIKE 'pg_toast%' AND cmd.schema_name NOT LIKE 'pg_temp%' THEN
      BEGIN
        EXECUTE format('alter table if exists %s enable row level security', cmd.object_identity);
        RAISE LOG 'rls_auto_enable: enabled RLS on %', cmd.object_identity;
      EXCEPTION
        WHEN OTHERS THEN
          RAISE LOG 'rls_auto_enable: failed to enable RLS on %', cmd.object_identity;
      END;
     ELSE
        RAISE LOG 'rls_auto_enable: skip % (either system schema or not in enforced list: %.)', cmd.object_identity, cmd.schema_name;
     END IF;
  END LOOP;
END;
$$;


ALTER FUNCTION "public"."rls_auto_enable"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."scenario_create"("base_portfolio" "text", "scenario_name" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
begin
  return jsonb_build_object(
    'scenario_created', true,
    'base_portfolio', base_portfolio,
    'scenario_name', scenario_name
  );
end;
$$;


ALTER FUNCTION "public"."scenario_create"("base_portfolio" "text", "scenario_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."scenario_drilldown"("scenario_name" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
begin
  return jsonb_build_object(
    'scenario', scenario_name,
    'details', 'drilldown_placeholder'
  );
end;
$$;


ALTER FUNCTION "public"."scenario_drilldown"("scenario_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."scenario_evaluate"("scenario_name" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
begin
  return jsonb_build_object(
    'scenario', scenario_name,
    'status', 'evaluation_placeholder'
  );
end;
$$;


ALTER FUNCTION "public"."scenario_evaluate"("scenario_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."trigger_cleanup_expired_locks"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  PERFORM cleanup_expired_locks();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."trigger_cleanup_expired_locks"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_dashboard_configs_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_dashboard_configs_updated_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_widget_notes_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_widget_notes_updated_at"() OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."cell_locks" (
    "lock_id" "text" DEFAULT ("gen_random_uuid"())::"text" NOT NULL,
    "risk_object_id" "text" NOT NULL,
    "field_name" "text" NOT NULL,
    "user_id" "text" NOT NULL,
    "user_name" "text" NOT NULL,
    "user_color" "text" NOT NULL,
    "session_id" "text" NOT NULL,
    "locked_at" timestamp with time zone DEFAULT "now"(),
    "expires_at" timestamp with time zone DEFAULT ("now"() + '00:00:30'::interval)
);

ALTER TABLE ONLY "public"."cell_locks" REPLICA IDENTITY FULL;


ALTER TABLE "public"."cell_locks" OWNER TO "postgres";


COMMENT ON TABLE "public"."cell_locks" IS 'Tracks active cell locks for multiplayer editing in DataList';



CREATE TABLE IF NOT EXISTS "public"."coverage" (
    "coverage_id" "text" NOT NULL,
    "risk_object_id" "text" NOT NULL,
    "loss_id" "text" NOT NULL,
    "policy_layer_id" "text" NOT NULL,
    "main_coverage_type" "text" NOT NULL
);


ALTER TABLE "public"."coverage" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."dashboard_configs" (
    "config_id" "text" DEFAULT ("gen_random_uuid"())::"text" NOT NULL,
    "portfolio_name" "text" NOT NULL,
    "widgets" "jsonb" DEFAULT '[]'::"jsonb" NOT NULL,
    "created_by_user_id" "text" NOT NULL,
    "created_by_user_name" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."dashboard_configs" OWNER TO "postgres";


COMMENT ON TABLE "public"."dashboard_configs" IS 'Stores dashboard configurations including widget layouts for collaborative editing';



CREATE TABLE IF NOT EXISTS "public"."deductibles" (
    "deductibles_id" "text" NOT NULL,
    "coverage_id" "text" NOT NULL,
    "subcoverage" "text" NOT NULL,
    "decutibles_scope" "text" NOT NULL,
    "decutibles_type" "text" NOT NULL,
    "decutibles_option" "text" NOT NULL,
    "amount" double precision NOT NULL,
    "currency" "text" NOT NULL
);


ALTER TABLE "public"."deductibles" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."exclusions" (
    "exclusion_id" "text" NOT NULL,
    "coverage_id" "text" NOT NULL,
    "exclusion_type" "text" NOT NULL
);


ALTER TABLE "public"."exclusions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."limits" (
    "limits_id" "text" NOT NULL,
    "coverage_id" "text" NOT NULL,
    "subcoverage" "text" NOT NULL,
    "limits_scope" "text" NOT NULL,
    "limits_type" "text" NOT NULL,
    "limits_option" "text" NOT NULL,
    "amount" double precision NOT NULL,
    "currency" "text" NOT NULL
);


ALTER TABLE "public"."limits" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."location_snapshots" (
    "location_snapshot_id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "snapshot_date" timestamp with time zone NOT NULL,
    "risk_object_id" "text" NOT NULL,
    "portfolio_name" "text" NOT NULL,
    "snapshot_data" "jsonb" NOT NULL,
    "location_name" "text",
    "combined_risk_score" numeric,
    "total_assets" numeric,
    "country" "text",
    "city" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "text" DEFAULT 'system'::"text",
    "address_quality" "text",
    "building_height" double precision,
    "building_value" double precision,
    "business_interruption_limit" double precision,
    "business_interruption_value" double precision,
    "business_location_id" "text",
    "business_unit_code" "text",
    "business_unit_name" "text",
    "cctv" "text",
    "combined_limit" double precision,
    "combined_total_sum_insured" double precision,
    "construction_risk_score" double precision,
    "contents_value" double precision,
    "cooling_type" "text",
    "currency" "text",
    "data_readiness_asset_values" integer,
    "data_readiness_core_attributes" integer,
    "data_readiness_location_data" integer,
    "data_readiness_overall" integer,
    "data_readiness_secondary_modifiers" integer,
    "distance_to_airport" double precision,
    "distance_to_city_center" double precision,
    "distance_to_coast" double precision,
    "distance_to_forest" double precision,
    "distance_to_industrial_area" double precision,
    "distance_to_main_road" double precision,
    "distance_to_railway" double precision,
    "distance_to_river" double precision,
    "earthquake_exposure_count" integer,
    "earthquake_zone" "text",
    "exposure_risk_score" double precision,
    "external_wall_type" "text",
    "fire_alarm" "text",
    "fire_protection_class" "text",
    "firestation_distance" double precision,
    "firestation_id" "text",
    "firestation_name" "text",
    "flood_zone" "text",
    "floor_area" double precision,
    "floor_type" "text",
    "geo_json" "jsonb",
    "has_basement" boolean,
    "has_emergency_power" boolean,
    "heating_type" "text",
    "internal_wall_type" "text",
    "intrusion_alarm" "text",
    "last_renovation_year" integer,
    "lightning_exposure_count" integer,
    "location_description" "text",
    "location_label" "text",
    "location_number" "text",
    "material_damage_limit" double precision,
    "maximum_possible_loss_business_interruption" double precision,
    "maximum_possible_loss_combined" double precision,
    "maximum_possible_loss_material_damage" double precision,
    "nat_cat_comment" "text",
    "nat_cat_risk_score" double precision,
    "natural_catastrophe_zone" "text",
    "number_of_risks" numeric,
    "occupancy_name_pic3" "text",
    "occupancy_risk_score" double precision,
    "occupancy_type_internal" "text",
    "occupancy_type_pic3" "text",
    "polygon_size_km2" double precision,
    "port_distance" double precision,
    "port_id" "text",
    "port_name" "text",
    "present_hazard_city" "text",
    "present_hazard_country" "text",
    "present_hazard_percent_tav" double precision,
    "present_hazard_port" "text",
    "present_hazard_risk_level" "text",
    "protection_risk_score" double precision,
    "proximity_to_fire_hydrant" double precision,
    "proximity_to_fire_station" double precision,
    "riot_risk_score" double precision,
    "riot_zone" "text",
    "risk_engine_comment" "text",
    "risk_severity" "text",
    "roof_covering" "text",
    "roof_insulation" "text",
    "roof_type" "text",
    "sprinkler_coverage" "text",
    "sprinkler_type" "text",
    "stock_value" double precision,
    "stormsurge_exposure_count" integer,
    "terrorism_zone" "text",
    "theft_protection_class" "text",
    "theft_risk_score" double precision,
    "theft_zone" "text",
    "underwriter_comment" "text",
    "unique_location_id" "text",
    "urbanisation_index" double precision,
    "windstorm_zone" "text"
);


ALTER TABLE "public"."location_snapshots" OWNER TO "postgres";


COMMENT ON TABLE "public"."location_snapshots" IS 'Historical snapshots of individual locations with full granular property data from risk_object_property. Contains 125 total fields for comprehensive temporal analysis.';



COMMENT ON COLUMN "public"."location_snapshots"."snapshot_date" IS 'Date when this snapshot was taken (typically 1st of each month)';



COMMENT ON COLUMN "public"."location_snapshots"."risk_object_id" IS 'Reference to the risk object (location) this snapshot represents';



COMMENT ON COLUMN "public"."location_snapshots"."snapshot_data" IS 'Complete LocationData object stored as JSONB containing all 100+ attributes';



COMMENT ON COLUMN "public"."location_snapshots"."location_name" IS 'Denormalized location name for quick filtering';



COMMENT ON COLUMN "public"."location_snapshots"."combined_risk_score" IS 'Denormalized overall risk score for quick filtering';



COMMENT ON COLUMN "public"."location_snapshots"."total_assets" IS 'Denormalized total asset value for quick filtering';



CREATE TABLE IF NOT EXISTS "public"."loss" (
    "loss_id" "text" NOT NULL,
    "policy_id" "text" NOT NULL,
    "is_claim" boolean NOT NULL,
    "is_large_claim" boolean,
    "currency" "text" NOT NULL,
    "indemnity_amount" double precision,
    "expense_amount" double precision,
    "total_loss_amount" double precision,
    "indemnity_reserve" double precision,
    "expense_reserve" double precision,
    "total_reserve" double precision,
    "indemnity_paid" double precision,
    "expense_paid" double precision,
    "total_paid" double precision,
    "loss_total" double precision,
    "deductible" double precision,
    "claim_notification_date" "date",
    "date_of_loss" "date",
    "label" "text",
    "description" "text",
    "claim_handler" "text",
    "status" "text",
    "claims_subrogation" boolean,
    "claims_provenue" boolean,
    "loss_event_id" "text"
);


ALTER TABLE "public"."loss" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."loss_automotive_specific" (
    "loss_automotive_specific_id" "text" NOT NULL,
    "loss_id" "text" NOT NULL,
    "vehicle_type" "text",
    "vehicle_subtype" "text",
    "vehicle_brand" "text",
    "vehicle_model" "text",
    "vehicle_year_of_manufacture" integer,
    "vehicle_identification_number" "text",
    "licence_plate" "text",
    "cause_of_loss" "text",
    "damage_description" "text",
    "repair_description" "text",
    "repair_cost" double precision,
    "replacement_cost" double precision,
    "residual_value" double precision,
    "driver_age" integer,
    "driver_experience_years" integer,
    "driver_gender" "text",
    "shipment_id" "text"
);


ALTER TABLE "public"."loss_automotive_specific" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."loss_event" (
    "loss_event_id" "text" NOT NULL,
    "type" "text" NOT NULL,
    "sub_type" "text",
    "label" "text",
    "description" "text"
);


ALTER TABLE "public"."loss_event" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."loss_machine_liability_specific" (
    "loss_machine_liability_specific_id" "text" NOT NULL,
    "loss_id" "text" NOT NULL,
    "machine_type" "text",
    "machine_subtype" "text",
    "machine_year_of_manufacture" integer,
    "serial_number" "text",
    "cause_of_loss" "text",
    "damage_description" "text",
    "repair_description" "text",
    "downtime_days" double precision,
    "replacement_cost" double precision,
    "repair_cost" double precision,
    "residual_value" double precision
);


ALTER TABLE "public"."loss_machine_liability_specific" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."physical_location" (
    "physical_location_id" "text" NOT NULL,
    "postal_address_id" "text" NOT NULL,
    "latitude" double precision,
    "longitude" double precision,
    "elevation" double precision,
    "cresta_zone" "text",
    "cresta_zone_ida" "text",
    "geo_code_json" "text",
    "geo_code_hash" "text"
);


ALTER TABLE "public"."physical_location" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."policy" (
    "policy_id" "text" NOT NULL,
    "business_policy_id" "text" NOT NULL,
    "name" "text" NOT NULL,
    "currency" "text" NOT NULL,
    "broker_name" "text",
    "broker_id" "text",
    "carrier" "text",
    "inception_date" "date",
    "expiration_date" "date",
    "label" "text" NOT NULL,
    "description" "text"
);


ALTER TABLE "public"."policy" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."policy_layer" (
    "policy_layer_id" "text" NOT NULL,
    "policy_id" "text" NOT NULL,
    "main_line_of_business" "text" NOT NULL,
    "sub_line_of_business" "text",
    "policy_limit_amount" double precision,
    "policy_limit_currency" "text" NOT NULL,
    "layer_type" "text",
    "layer_order" integer DEFAULT 0,
    CONSTRAINT "chk_policy_layer_type" CHECK (("layer_type" = ANY (ARRAY['primary'::"text", 'working'::"text", 'excess'::"text", 'government'::"text", 'other'::"text"])))
);


ALTER TABLE "public"."policy_layer" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."policy_premium" (
    "policy_premium_id" "text" NOT NULL,
    "policy_id" "text" NOT NULL,
    "coverage_id" "text" NOT NULL,
    "gross_premium" numeric NOT NULL,
    "due_date" "date",
    "deduction_type" "text",
    "unit" "text",
    "amount" double precision,
    "currency" "text" NOT NULL
);


ALTER TABLE "public"."policy_premium" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."portfolio_shares" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "owner_user_id" "text" NOT NULL,
    "owner_user_email" "text" NOT NULL,
    "owner_team_id" "uuid" NOT NULL,
    "recipient_team_id" "uuid" NOT NULL,
    "recipient_team_name" "text",
    "shared_portfolio_name" "text",
    "shared_risk_object_ids" "text"[],
    "access_level" "text" DEFAULT 'view'::"text",
    "can_reshare" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "shared_at" timestamp with time zone DEFAULT "now"(),
    "revoked_at" timestamp with time zone,
    "is_active" boolean DEFAULT true,
    "share_type" "text" DEFAULT 'internal'::"text"
);


ALTER TABLE "public"."portfolio_shares" OWNER TO "postgres";


COMMENT ON TABLE "public"."portfolio_shares" IS 'Tracks sharing relationships between teams for portfolios and locations';



COMMENT ON COLUMN "public"."portfolio_shares"."shared_risk_object_ids" IS 'Array of risk_object IDs that are shared with the recipient team';



COMMENT ON COLUMN "public"."portfolio_shares"."can_reshare" IS 'Whether the recipient can re-share these locations with others';



COMMENT ON COLUMN "public"."portfolio_shares"."is_active" IS 'Whether the share is currently active (false when revoked)';



CREATE TABLE IF NOT EXISTS "public"."portfolio_snapshots" (
    "snapshot_id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "portfolio_name" "text" NOT NULL,
    "snapshot_date" timestamp with time zone NOT NULL,
    "location_count" integer NOT NULL,
    "total_asset_value" numeric,
    "average_risk_score" numeric,
    "total_insured_value" numeric,
    "annual_expected_loss_combined" numeric,
    "annual_expected_loss_material_damage" numeric,
    "annual_expected_loss_business_interruption" numeric,
    "risk_distribution" "jsonb",
    "top_risk_categories" "jsonb",
    "avg_flood_risk_score" numeric,
    "avg_earthquake_risk_score" numeric,
    "avg_windstorm_risk_score" numeric,
    "avg_fire_risk_score" numeric,
    "avg_terrorism_risk_score" numeric,
    "country_distribution" "jsonb",
    "geographic_concentration_index" numeric,
    "total_coverage_value" numeric,
    "coverage_gap_percentage" numeric,
    "max_possible_loss_combined" numeric,
    "max_possible_loss_material_damage" numeric,
    "avg_construction_year" numeric,
    "avg_number_of_floors" numeric,
    "added_location_ids" "text"[],
    "removed_location_ids" "text"[],
    "created_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "text",
    "notes" "text"
);


ALTER TABLE "public"."portfolio_snapshots" OWNER TO "postgres";


COMMENT ON TABLE "public"."portfolio_snapshots" IS 'Stores historical snapshots of portfolio metrics taken at 30-day intervals for temporal comparison';



COMMENT ON COLUMN "public"."portfolio_snapshots"."snapshot_date" IS 'Date when this snapshot was taken';



COMMENT ON COLUMN "public"."portfolio_snapshots"."risk_distribution" IS 'Distribution of locations by risk level (low/medium/high)';



COMMENT ON COLUMN "public"."portfolio_snapshots"."top_risk_categories" IS 'Top risk categories with counts';



COMMENT ON COLUMN "public"."portfolio_snapshots"."geographic_concentration_index" IS 'Herfindahl index: 0 = evenly distributed, 1 = concentrated';



COMMENT ON COLUMN "public"."portfolio_snapshots"."added_location_ids" IS 'Location IDs added since previous snapshot';



COMMENT ON COLUMN "public"."portfolio_snapshots"."removed_location_ids" IS 'Location IDs removed since previous snapshot';



CREATE TABLE IF NOT EXISTS "public"."postal_address" (
    "postal_address_id" "text" NOT NULL,
    "country" "text" NOT NULL,
    "region" "text",
    "city" "text",
    "postal_code" "text",
    "street_address" "text",
    "house_number" "text",
    "state" "text"
);


ALTER TABLE "public"."postal_address" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."risk_object" (
    "risk_object_id" "text" NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "portfolio_name" "text",
    "postal_address_id" "text",
    "physical_location_id" "text",
    "business_id" "text",
    "type" "text"
);


ALTER TABLE "public"."risk_object" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."risk_object_event" (
    "event_id" "text" DEFAULT ('evt_'::"text" || ("gen_random_uuid"())::"text") NOT NULL,
    "risk_object_id" "text" NOT NULL,
    "name" "text" NOT NULL,
    "date" timestamp with time zone,
    "type" "text" NOT NULL,
    "assets_impacted" integer,
    "tav" double precision,
    "wind_speed" double precision,
    "flood_depth" double precision,
    "magnitude" double precision,
    "temperature" double precision,
    "burn_area" double precision,
    "precipitation_deficit" double precision,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."risk_object_event" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."risk_object_peril_distribution" (
    "peril_distribution_id" "text" DEFAULT ('peril_'::"text" || ("gen_random_uuid"())::"text") NOT NULL,
    "risk_object_id" "text" NOT NULL,
    "peril_name" "text" NOT NULL,
    "percentage" integer NOT NULL
);


ALTER TABLE "public"."risk_object_peril_distribution" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."risk_object_portfolio" (
    "risk_object_portfolio_id" "text" NOT NULL,
    "name" "text" NOT NULL,
    "description" "text"
);


ALTER TABLE "public"."risk_object_portfolio" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."risk_object_property" (
    "risk_object_property_id" "text" NOT NULL,
    "unique_location_id" "text",
    "location_number" "text",
    "location_label" "text",
    "location_description" "text",
    "business_location_id" "text",
    "business_unit_name" "text",
    "business_unit_code" "text",
    "occupancy_type_pic3" "text",
    "occupancy_name_pic3" "text",
    "number_of_risks" numeric,
    "currency" "text",
    "combined_total_sum_insured" double precision,
    "maximum_possible_loss_combined" double precision,
    "maximum_possible_loss_material_damage" double precision,
    "maximum_possible_loss_business_interruption" double precision,
    "annual_expected_loss_combined" double precision,
    "annual_expected_loss_material_damage" double precision,
    "annual_expected_loss_business_interruption" double precision,
    "combined_limit" double precision,
    "material_damage_limit" double precision,
    "business_interruption_limit" double precision,
    "address_quality" "text",
    "natural_catastrophe_zone" "text",
    "fire_protection_class" "text",
    "theft_protection_class" "text",
    "construction_type" "text",
    "construction_year" integer,
    "last_renovation_year" integer,
    "number_of_floors" integer,
    "floor_area" double precision,
    "building_height" double precision,
    "sprinkler_coverage" "text",
    "sprinkler_type" "text",
    "fire_alarm" "text",
    "intrusion_alarm" "text",
    "cctv" "text",
    "has_basement" boolean,
    "roof_type" "text",
    "roof_covering" "text",
    "roof_insulation" "text",
    "external_wall_type" "text",
    "internal_wall_type" "text",
    "floor_type" "text",
    "heating_type" "text",
    "cooling_type" "text",
    "has_emergency_power" boolean,
    "flood_zone" "text",
    "earthquake_zone" "text",
    "windstorm_zone" "text",
    "theft_zone" "text",
    "riot_zone" "text",
    "terrorism_zone" "text",
    "proximity_to_fire_station" double precision,
    "proximity_to_fire_hydrant" double precision,
    "distance_to_coast" double precision,
    "distance_to_river" double precision,
    "distance_to_forest" double precision,
    "distance_to_industrial_area" double precision,
    "distance_to_airport" double precision,
    "distance_to_railway" double precision,
    "distance_to_main_road" double precision,
    "occupancy_type_internal" "text",
    "occupancy_risk_score" double precision,
    "construction_risk_score" double precision,
    "protection_risk_score" double precision,
    "exposure_risk_score" double precision,
    "combined_risk_score" double precision,
    "flood_risk_score" double precision,
    "earthquake_risk_score" double precision,
    "windstorm_risk_score" double precision,
    "theft_risk_score" double precision,
    "riot_risk_score" double precision,
    "terrorism_risk_score" double precision,
    "fire_risk_score" double precision,
    "nat_cat_risk_score" double precision,
    "total_insured_value" double precision,
    "building_value" double precision,
    "contents_value" double precision,
    "stock_value" double precision,
    "business_interruption_value" double precision,
    "port_id" "text",
    "port_name" "text",
    "firestation_id" "text",
    "firestation_name" "text",
    "port_distance" double precision,
    "firestation_distance" double precision,
    "distance_to_city_center" double precision,
    "urbanisation_index" double precision,
    "nat_cat_comment" "text",
    "risk_engine_comment" "text",
    "underwriter_comment" "text",
    "risk_object_id" "text",
    "risk_severity" "text",
    "total_assets" integer,
    "polygon_size_km2" double precision,
    "geo_json" "jsonb",
    "earthquake_exposure_count" integer,
    "lightning_exposure_count" integer,
    "stormsurge_exposure_count" integer,
    "data_readiness_location_data" integer,
    "data_readiness_asset_values" integer,
    "data_readiness_core_attributes" integer,
    "data_readiness_secondary_modifiers" integer,
    "data_readiness_overall" integer,
    "present_hazard_risk_level" "text",
    "present_hazard_percent_tav" double precision,
    "present_hazard_port" "text",
    "present_hazard_country" "text",
    "present_hazard_city" "text"
);


ALTER TABLE "public"."risk_object_property" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."risk_object_task" (
    "task_id" "text" DEFAULT ('task_'::"text" || ("gen_random_uuid"())::"text") NOT NULL,
    "risk_object_id" "text" NOT NULL,
    "title" "text" NOT NULL,
    "description" "text",
    "status" "text" DEFAULT 'pending'::"text",
    "priority" "text",
    "assigned_to" "text",
    "due_date" timestamp with time zone,
    "completed_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."risk_object_task" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."team_members" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "team_id" "uuid",
    "user_email" "text" NOT NULL,
    "user_name" "text",
    "role" "text" DEFAULT 'member'::"text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."team_members" OWNER TO "postgres";


COMMENT ON TABLE "public"."team_members" IS 'Maps users to teams with their roles';



CREATE TABLE IF NOT EXISTS "public"."team_risk_objects" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "team_id" "uuid",
    "risk_object_id" "text",
    "access_level" "text" DEFAULT 'read'::"text",
    "granted_at" timestamp with time zone DEFAULT "now"(),
    "granted_by" "text"
);


ALTER TABLE "public"."team_risk_objects" OWNER TO "postgres";


COMMENT ON TABLE "public"."team_risk_objects" IS 'Controls which teams have access to which risk objects';



CREATE TABLE IF NOT EXISTS "public"."teams" (
    "team_id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "team_name" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "team_type" "text" DEFAULT 'internal'::"text",
    "organization_name" "text"
);


ALTER TABLE "public"."teams" OWNER TO "postgres";


COMMENT ON TABLE "public"."teams" IS 'Stores team information for multi-tenant access control';



CREATE TABLE IF NOT EXISTS "public"."widget_notes" (
    "note_id" "text" DEFAULT ("gen_random_uuid"())::"text" NOT NULL,
    "widget_id" "text" NOT NULL,
    "content" "text" DEFAULT ''::"text",
    "updated_by" "text" NOT NULL,
    "updated_by_name" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);

ALTER TABLE ONLY "public"."widget_notes" REPLICA IDENTITY FULL;


ALTER TABLE "public"."widget_notes" OWNER TO "postgres";


COMMENT ON TABLE "public"."widget_notes" IS 'Stores collaborative note content for Notes widgets';



ALTER TABLE ONLY "public"."cell_locks"
    ADD CONSTRAINT "cell_locks_pkey" PRIMARY KEY ("lock_id");



ALTER TABLE ONLY "public"."coverage"
    ADD CONSTRAINT "coverage_pkey" PRIMARY KEY ("coverage_id");



ALTER TABLE ONLY "public"."dashboard_configs"
    ADD CONSTRAINT "dashboard_configs_pkey" PRIMARY KEY ("config_id");



ALTER TABLE ONLY "public"."deductibles"
    ADD CONSTRAINT "deductibles_pkey" PRIMARY KEY ("deductibles_id");



ALTER TABLE ONLY "public"."exclusions"
    ADD CONSTRAINT "exclusions_pkey" PRIMARY KEY ("exclusion_id");



ALTER TABLE ONLY "public"."limits"
    ADD CONSTRAINT "limits_pkey" PRIMARY KEY ("limits_id");



ALTER TABLE ONLY "public"."location_snapshots"
    ADD CONSTRAINT "location_snapshots_pkey" PRIMARY KEY ("location_snapshot_id");



ALTER TABLE ONLY "public"."location_snapshots"
    ADD CONSTRAINT "location_snapshots_risk_object_id_snapshot_date_key" UNIQUE ("risk_object_id", "snapshot_date");



ALTER TABLE ONLY "public"."loss_automotive_specific"
    ADD CONSTRAINT "loss_automotive_specific_pkey" PRIMARY KEY ("loss_automotive_specific_id");



ALTER TABLE ONLY "public"."loss_event"
    ADD CONSTRAINT "loss_event_pkey" PRIMARY KEY ("loss_event_id");



ALTER TABLE ONLY "public"."loss_machine_liability_specific"
    ADD CONSTRAINT "loss_machine_liability_specific_pkey" PRIMARY KEY ("loss_machine_liability_specific_id");



ALTER TABLE ONLY "public"."loss"
    ADD CONSTRAINT "loss_pkey" PRIMARY KEY ("loss_id");



ALTER TABLE ONLY "public"."physical_location"
    ADD CONSTRAINT "physical_location_pkey" PRIMARY KEY ("physical_location_id");



ALTER TABLE ONLY "public"."policy_layer"
    ADD CONSTRAINT "policy_layer_pkey" PRIMARY KEY ("policy_layer_id");



ALTER TABLE ONLY "public"."policy"
    ADD CONSTRAINT "policy_pkey" PRIMARY KEY ("policy_id");



ALTER TABLE ONLY "public"."policy_premium"
    ADD CONSTRAINT "policy_premium_pkey" PRIMARY KEY ("policy_premium_id");



ALTER TABLE ONLY "public"."portfolio_shares"
    ADD CONSTRAINT "portfolio_shares_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."portfolio_snapshots"
    ADD CONSTRAINT "portfolio_snapshots_pkey" PRIMARY KEY ("snapshot_id");



ALTER TABLE ONLY "public"."portfolio_snapshots"
    ADD CONSTRAINT "portfolio_snapshots_portfolio_name_snapshot_date_key" UNIQUE ("portfolio_name", "snapshot_date");



ALTER TABLE ONLY "public"."postal_address"
    ADD CONSTRAINT "postal_address_pkey" PRIMARY KEY ("postal_address_id");



ALTER TABLE ONLY "public"."risk_object_event"
    ADD CONSTRAINT "risk_object_event_pkey" PRIMARY KEY ("event_id");



ALTER TABLE ONLY "public"."risk_object_peril_distribution"
    ADD CONSTRAINT "risk_object_peril_distribution_pkey" PRIMARY KEY ("peril_distribution_id");



ALTER TABLE ONLY "public"."risk_object_peril_distribution"
    ADD CONSTRAINT "risk_object_peril_distribution_risk_object_id_peril_name_key" UNIQUE ("risk_object_id", "peril_name");



ALTER TABLE ONLY "public"."risk_object"
    ADD CONSTRAINT "risk_object_pkey" PRIMARY KEY ("risk_object_id");



ALTER TABLE ONLY "public"."risk_object_portfolio"
    ADD CONSTRAINT "risk_object_portfolio_pkey" PRIMARY KEY ("risk_object_portfolio_id");



ALTER TABLE ONLY "public"."risk_object_property"
    ADD CONSTRAINT "risk_object_property_pkey" PRIMARY KEY ("risk_object_property_id");



ALTER TABLE ONLY "public"."risk_object_task"
    ADD CONSTRAINT "risk_object_task_pkey" PRIMARY KEY ("task_id");



ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_team_id_user_email_key" UNIQUE ("team_id", "user_email");



ALTER TABLE ONLY "public"."team_risk_objects"
    ADD CONSTRAINT "team_risk_objects_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."team_risk_objects"
    ADD CONSTRAINT "team_risk_objects_team_id_risk_object_id_key" UNIQUE ("team_id", "risk_object_id");



ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_pkey" PRIMARY KEY ("team_id");



ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_team_name_key" UNIQUE ("team_name");



ALTER TABLE ONLY "public"."cell_locks"
    ADD CONSTRAINT "unique_cell_lock" UNIQUE ("risk_object_id", "field_name");



ALTER TABLE ONLY "public"."dashboard_configs"
    ADD CONSTRAINT "unique_portfolio_config" UNIQUE ("portfolio_name");



ALTER TABLE ONLY "public"."widget_notes"
    ADD CONSTRAINT "unique_widget_note" UNIQUE ("widget_id");



ALTER TABLE ONLY "public"."widget_notes"
    ADD CONSTRAINT "widget_notes_pkey" PRIMARY KEY ("note_id");



CREATE INDEX "idx_cell_locks_expires" ON "public"."cell_locks" USING "btree" ("expires_at");



CREATE INDEX "idx_cell_locks_object" ON "public"."cell_locks" USING "btree" ("risk_object_id");



CREATE INDEX "idx_cell_locks_session" ON "public"."cell_locks" USING "btree" ("session_id");



CREATE INDEX "idx_dashboard_configs_created_at" ON "public"."dashboard_configs" USING "btree" ("created_at");



CREATE INDEX "idx_dashboard_configs_portfolio" ON "public"."dashboard_configs" USING "btree" ("portfolio_name");



CREATE INDEX "idx_location_snapshots_data_gin" ON "public"."location_snapshots" USING "gin" ("snapshot_data");



CREATE INDEX "idx_location_snapshots_date" ON "public"."location_snapshots" USING "btree" ("snapshot_date" DESC);



CREATE INDEX "idx_location_snapshots_portfolio" ON "public"."location_snapshots" USING "btree" ("portfolio_name");



CREATE INDEX "idx_location_snapshots_portfolio_date" ON "public"."location_snapshots" USING "btree" ("portfolio_name", "snapshot_date" DESC);



CREATE INDEX "idx_location_snapshots_risk_object_date" ON "public"."location_snapshots" USING "btree" ("risk_object_id", "snapshot_date" DESC);



CREATE INDEX "idx_location_snapshots_risk_object_id" ON "public"."location_snapshots" USING "btree" ("risk_object_id");



CREATE INDEX "idx_location_snapshots_temporal" ON "public"."location_snapshots" USING "btree" ("risk_object_id", "snapshot_date" DESC);



CREATE INDEX "idx_loss_loss_event_id" ON "public"."loss" USING "btree" ("loss_event_id");



CREATE INDEX "idx_policy_layer_order" ON "public"."policy_layer" USING "btree" ("policy_id", "layer_order");



CREATE INDEX "idx_portfolio_shares_active" ON "public"."portfolio_shares" USING "btree" ("is_active") WHERE ("is_active" = true);



CREATE INDEX "idx_portfolio_shares_owner" ON "public"."portfolio_shares" USING "btree" ("owner_user_email", "owner_team_id");



CREATE INDEX "idx_portfolio_shares_recipient" ON "public"."portfolio_shares" USING "btree" ("recipient_team_id");



CREATE INDEX "idx_portfolio_shares_risk_objects" ON "public"."portfolio_shares" USING "gin" ("shared_risk_object_ids");



CREATE INDEX "idx_portfolio_snapshots_date" ON "public"."portfolio_snapshots" USING "btree" ("snapshot_date" DESC);



CREATE INDEX "idx_portfolio_snapshots_portfolio" ON "public"."portfolio_snapshots" USING "btree" ("portfolio_name");



CREATE INDEX "idx_portfolio_snapshots_portfolio_date" ON "public"."portfolio_snapshots" USING "btree" ("portfolio_name", "snapshot_date" DESC);



CREATE INDEX "idx_risk_object_event_risk_object_id" ON "public"."risk_object_event" USING "btree" ("risk_object_id");



CREATE INDEX "idx_risk_object_peril_distribution_risk_object_id" ON "public"."risk_object_peril_distribution" USING "btree" ("risk_object_id");



CREATE INDEX "idx_risk_object_postal_address_id" ON "public"."risk_object" USING "btree" ("postal_address_id");



CREATE INDEX "idx_risk_object_task_risk_object_id" ON "public"."risk_object_task" USING "btree" ("risk_object_id");



CREATE INDEX "idx_risk_object_task_status" ON "public"."risk_object_task" USING "btree" ("status");



CREATE INDEX "idx_team_members_team_id" ON "public"."team_members" USING "btree" ("team_id");



CREATE INDEX "idx_team_members_user_email" ON "public"."team_members" USING "btree" ("user_email");



CREATE INDEX "idx_team_risk_objects_risk_object_id" ON "public"."team_risk_objects" USING "btree" ("risk_object_id");



CREATE INDEX "idx_team_risk_objects_team_id" ON "public"."team_risk_objects" USING "btree" ("team_id");



CREATE INDEX "idx_widget_notes_updated_at" ON "public"."widget_notes" USING "btree" ("updated_at");



CREATE INDEX "idx_widget_notes_widget_id" ON "public"."widget_notes" USING "btree" ("widget_id");



CREATE OR REPLACE TRIGGER "trigger_cleanup_locks" AFTER INSERT OR UPDATE ON "public"."cell_locks" FOR EACH STATEMENT EXECUTE FUNCTION "public"."trigger_cleanup_expired_locks"();



CREATE OR REPLACE TRIGGER "trigger_update_dashboard_configs_updated_at" BEFORE UPDATE ON "public"."dashboard_configs" FOR EACH ROW EXECUTE FUNCTION "public"."update_dashboard_configs_updated_at"();



CREATE OR REPLACE TRIGGER "trigger_update_widget_notes_updated_at" BEFORE UPDATE ON "public"."widget_notes" FOR EACH ROW EXECUTE FUNCTION "public"."update_widget_notes_updated_at"();



ALTER TABLE ONLY "public"."coverage"
    ADD CONSTRAINT "coverage_risk_object_id_fkey" FOREIGN KEY ("risk_object_id") REFERENCES "public"."risk_object"("risk_object_id");



ALTER TABLE ONLY "public"."exclusions"
    ADD CONSTRAINT "exclusions_coverage_id_fkey" FOREIGN KEY ("coverage_id") REFERENCES "public"."coverage"("coverage_id");



ALTER TABLE ONLY "public"."portfolio_shares"
    ADD CONSTRAINT "fk_owner_team" FOREIGN KEY ("owner_team_id") REFERENCES "public"."teams"("team_id");



ALTER TABLE ONLY "public"."portfolio_shares"
    ADD CONSTRAINT "fk_recipient_team" FOREIGN KEY ("recipient_team_id") REFERENCES "public"."teams"("team_id");



ALTER TABLE ONLY "public"."limits"
    ADD CONSTRAINT "limits_coverage_id_fkey" FOREIGN KEY ("coverage_id") REFERENCES "public"."coverage"("coverage_id");



ALTER TABLE ONLY "public"."loss_automotive_specific"
    ADD CONSTRAINT "loss_automotive_specific_loss_id_fkey" FOREIGN KEY ("loss_id") REFERENCES "public"."loss"("loss_id");



ALTER TABLE ONLY "public"."loss"
    ADD CONSTRAINT "loss_loss_event_fkey" FOREIGN KEY ("loss_event_id") REFERENCES "public"."loss_event"("loss_event_id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."loss_machine_liability_specific"
    ADD CONSTRAINT "loss_machine_liability_specific_loss_id_fkey" FOREIGN KEY ("loss_id") REFERENCES "public"."loss"("loss_id");



ALTER TABLE ONLY "public"."loss"
    ADD CONSTRAINT "loss_policy_id_fkey" FOREIGN KEY ("policy_id") REFERENCES "public"."policy"("policy_id");



ALTER TABLE ONLY "public"."physical_location"
    ADD CONSTRAINT "physical_location_postal_address_id_fkey" FOREIGN KEY ("postal_address_id") REFERENCES "public"."postal_address"("postal_address_id");



ALTER TABLE ONLY "public"."policy_layer"
    ADD CONSTRAINT "policy_layer_policy_id_fkey" FOREIGN KEY ("policy_id") REFERENCES "public"."policy"("policy_id");



ALTER TABLE ONLY "public"."policy_premium"
    ADD CONSTRAINT "policy_premium_policy_id_fkey" FOREIGN KEY ("policy_id") REFERENCES "public"."policy"("policy_id");



ALTER TABLE ONLY "public"."risk_object_event"
    ADD CONSTRAINT "risk_object_event_risk_object_id_fkey" FOREIGN KEY ("risk_object_id") REFERENCES "public"."risk_object"("risk_object_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."risk_object_peril_distribution"
    ADD CONSTRAINT "risk_object_peril_distribution_risk_object_id_fkey" FOREIGN KEY ("risk_object_id") REFERENCES "public"."risk_object"("risk_object_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."risk_object"
    ADD CONSTRAINT "risk_object_physical_location_id_fkey" FOREIGN KEY ("physical_location_id") REFERENCES "public"."physical_location"("physical_location_id");



ALTER TABLE ONLY "public"."risk_object"
    ADD CONSTRAINT "risk_object_postal_address_id_fkey" FOREIGN KEY ("postal_address_id") REFERENCES "public"."postal_address"("postal_address_id");



ALTER TABLE ONLY "public"."risk_object_property"
    ADD CONSTRAINT "risk_object_property_risk_object_id_fkey" FOREIGN KEY ("risk_object_id") REFERENCES "public"."risk_object"("risk_object_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."risk_object_task"
    ADD CONSTRAINT "risk_object_task_risk_object_id_fkey" FOREIGN KEY ("risk_object_id") REFERENCES "public"."risk_object"("risk_object_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_team_id_fkey" FOREIGN KEY ("team_id") REFERENCES "public"."teams"("team_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."team_risk_objects"
    ADD CONSTRAINT "team_risk_objects_risk_object_id_fkey" FOREIGN KEY ("risk_object_id") REFERENCES "public"."risk_object"("risk_object_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."team_risk_objects"
    ADD CONSTRAINT "team_risk_objects_team_id_fkey" FOREIGN KEY ("team_id") REFERENCES "public"."teams"("team_id") ON DELETE CASCADE;



CREATE POLICY "Allow all read access to risk_object_event" ON "public"."risk_object_event" FOR SELECT USING (true);



CREATE POLICY "Allow all read access to risk_object_peril_distribution" ON "public"."risk_object_peril_distribution" FOR SELECT USING (true);



CREATE POLICY "Allow all read access to risk_object_task" ON "public"."risk_object_task" FOR SELECT USING (true);



CREATE POLICY "Allow all write access to risk_object_event" ON "public"."risk_object_event" USING (true);



CREATE POLICY "Allow all write access to risk_object_peril_distribution" ON "public"."risk_object_peril_distribution" USING (true);



CREATE POLICY "Allow all write access to risk_object_task" ON "public"."risk_object_task" USING (true);



CREATE POLICY "Allow delete configs" ON "public"."dashboard_configs" FOR DELETE USING (true);



CREATE POLICY "Allow delete notes" ON "public"."widget_notes" FOR DELETE USING (true);



CREATE POLICY "Allow delete own locks" ON "public"."cell_locks" FOR DELETE USING (true);



CREATE POLICY "Allow insert configs" ON "public"."dashboard_configs" FOR INSERT WITH CHECK (true);



CREATE POLICY "Allow insert locks" ON "public"."cell_locks" FOR INSERT WITH CHECK (true);



CREATE POLICY "Allow insert notes" ON "public"."widget_notes" FOR INSERT WITH CHECK (true);



CREATE POLICY "Allow public insert access on physical_location" ON "public"."physical_location" FOR INSERT WITH CHECK (true);



CREATE POLICY "Allow public insert access on postal_address" ON "public"."postal_address" FOR INSERT WITH CHECK (true);



CREATE POLICY "Allow public insert access on risk_object" ON "public"."risk_object" FOR INSERT WITH CHECK (true);



CREATE POLICY "Allow public insert access on risk_object_property" ON "public"."risk_object_property" FOR INSERT WITH CHECK (true);



CREATE POLICY "Allow public read access on coverage" ON "public"."coverage" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on deductibles" ON "public"."deductibles" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on exclusions" ON "public"."exclusions" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on limits" ON "public"."limits" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on loss" ON "public"."loss" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on loss_automotive_specific" ON "public"."loss_automotive_specific" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on loss_event" ON "public"."loss_event" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on loss_machine_liability_specific" ON "public"."loss_machine_liability_specific" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on physical_location" ON "public"."physical_location" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on policy" ON "public"."policy" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on policy_layer" ON "public"."policy_layer" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on policy_premium" ON "public"."policy_premium" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on postal_address" ON "public"."postal_address" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on risk_object" ON "public"."risk_object" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on risk_object_portfolio" ON "public"."risk_object_portfolio" FOR SELECT USING (true);



CREATE POLICY "Allow public read access on risk_object_property" ON "public"."risk_object_property" FOR SELECT USING (true);



CREATE POLICY "Allow public update access on physical_location" ON "public"."physical_location" FOR UPDATE USING (true) WITH CHECK (true);



CREATE POLICY "Allow public update access on postal_address" ON "public"."postal_address" FOR UPDATE USING (true) WITH CHECK (true);



CREATE POLICY "Allow public update access on risk_object" ON "public"."risk_object" FOR UPDATE USING (true) WITH CHECK (true);



CREATE POLICY "Allow public update access on risk_object_property" ON "public"."risk_object_property" FOR UPDATE USING (true) WITH CHECK (true);



CREATE POLICY "Allow read access to all configs" ON "public"."dashboard_configs" FOR SELECT USING (true);



CREATE POLICY "Allow read access to all locks" ON "public"."cell_locks" FOR SELECT USING (true);



CREATE POLICY "Allow read access to all notes" ON "public"."widget_notes" FOR SELECT USING (true);



CREATE POLICY "Allow read access to team_members" ON "public"."team_members" FOR SELECT USING (true);



CREATE POLICY "Allow read access to team_risk_objects" ON "public"."team_risk_objects" FOR SELECT USING (true);



CREATE POLICY "Allow read access to teams" ON "public"."teams" FOR SELECT USING (true);



CREATE POLICY "Allow update configs" ON "public"."dashboard_configs" FOR UPDATE USING (true) WITH CHECK (true);



CREATE POLICY "Allow update notes" ON "public"."widget_notes" FOR UPDATE USING (true) WITH CHECK (true);



CREATE POLICY "Allow update own locks" ON "public"."cell_locks" FOR UPDATE USING (true) WITH CHECK (true);



CREATE POLICY "Enable read access for all users" ON "public"."location_snapshots" FOR SELECT USING (true);



CREATE POLICY "Enable read access for all users" ON "public"."portfolio_shares" FOR SELECT USING (true);



CREATE POLICY "Enable read access for all users" ON "public"."portfolio_snapshots" FOR SELECT USING (true);



ALTER TABLE "public"."cell_locks" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."coverage" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."dashboard_configs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."deductibles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."exclusions" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."limits" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."loss" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."loss_automotive_specific" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."loss_event" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."loss_machine_liability_specific" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."physical_location" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."policy" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."policy_layer" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."policy_premium" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."portfolio_snapshots" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."postal_address" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."risk_object" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."risk_object_event" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."risk_object_peril_distribution" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."risk_object_portfolio" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."risk_object_property" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."risk_object_task" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."team_members" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."team_risk_objects" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."teams" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."widget_notes" ENABLE ROW LEVEL SECURITY;




ALTER PUBLICATION "supabase_realtime" OWNER TO "postgres";






ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."cell_locks";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."coverage";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."dashboard_configs";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."exclusions";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."limits";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."loss";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."loss_automotive_specific";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."loss_event";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."loss_machine_liability_specific";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."physical_location";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."policy";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."policy_layer";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."policy_premium";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."portfolio_shares";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."portfolio_snapshots";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."postal_address";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."risk_object";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."risk_object_event";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."risk_object_peril_distribution";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."risk_object_portfolio";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."risk_object_property";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."risk_object_task";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."team_members";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."team_risk_objects";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."teams";



GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";
























































































































































































































GRANT ALL ON FUNCTION "public"."anomaly_summary"("scope" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."anomaly_summary"("scope" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."anomaly_summary"("scope" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."cleanup_expired_locks"() TO "anon";
GRANT ALL ON FUNCTION "public"."cleanup_expired_locks"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cleanup_expired_locks"() TO "service_role";



GRANT ALL ON FUNCTION "public"."execute_dynamic_query"("query_text" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."execute_dynamic_query"("query_text" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."execute_dynamic_query"("query_text" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_location_snapshot_count"("p_location_id" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_location_snapshot_count"("p_location_id" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_location_snapshot_count"("p_location_id" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_portfolio_counts"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_portfolio_counts"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_portfolio_counts"() TO "service_role";



GRANT ALL ON FUNCTION "public"."outlier_list"("scope" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."outlier_list"("scope" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."outlier_list"("scope" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."random_between"("low" integer, "high" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."random_between"("low" integer, "high" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."random_between"("low" integer, "high" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."random_date"("start_date" "date", "end_date" "date") TO "anon";
GRANT ALL ON FUNCTION "public"."random_date"("start_date" "date", "end_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."random_date"("start_date" "date", "end_date" "date") TO "service_role";



GRANT ALL ON FUNCTION "public"."random_decimal"("low" numeric, "high" numeric) TO "anon";
GRANT ALL ON FUNCTION "public"."random_decimal"("low" numeric, "high" numeric) TO "authenticated";
GRANT ALL ON FUNCTION "public"."random_decimal"("low" numeric, "high" numeric) TO "service_role";



GRANT ALL ON FUNCTION "public"."recommend_actions"("scope" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."recommend_actions"("scope" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."recommend_actions"("scope" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."risk_band_distribution"("scope" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."risk_band_distribution"("scope" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."risk_band_distribution"("scope" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."risk_breakdown"("scope" "jsonb", "dimension" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."risk_breakdown"("scope" "jsonb", "dimension" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."risk_breakdown"("scope" "jsonb", "dimension" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."risk_compare"("portfolio_a" "text", "portfolio_b" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."risk_compare"("portfolio_a" "text", "portfolio_b" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."risk_compare"("portfolio_a" "text", "portfolio_b" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."risk_drivers"("scope" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."risk_drivers"("scope" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."risk_drivers"("scope" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."risk_summary"("scope" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."risk_summary"("scope" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."risk_summary"("scope" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."risk_summary"("scope" "jsonb", "time_window" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."risk_summary"("scope" "jsonb", "time_window" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."risk_summary"("scope" "jsonb", "time_window" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."risk_top_properties"("scope" "jsonb", "page_size" integer, "metric" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."risk_top_properties"("scope" "jsonb", "page_size" integer, "metric" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."risk_top_properties"("scope" "jsonb", "page_size" integer, "metric" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."risk_trend"("scope" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."risk_trend"("scope" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."risk_trend"("scope" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."rls_auto_enable"() TO "anon";
GRANT ALL ON FUNCTION "public"."rls_auto_enable"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."rls_auto_enable"() TO "service_role";



GRANT ALL ON FUNCTION "public"."scenario_create"("base_portfolio" "text", "scenario_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."scenario_create"("base_portfolio" "text", "scenario_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."scenario_create"("base_portfolio" "text", "scenario_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."scenario_drilldown"("scenario_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."scenario_drilldown"("scenario_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."scenario_drilldown"("scenario_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."scenario_evaluate"("scenario_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."scenario_evaluate"("scenario_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."scenario_evaluate"("scenario_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."trigger_cleanup_expired_locks"() TO "anon";
GRANT ALL ON FUNCTION "public"."trigger_cleanup_expired_locks"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."trigger_cleanup_expired_locks"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_dashboard_configs_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_dashboard_configs_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_dashboard_configs_updated_at"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_widget_notes_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_widget_notes_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_widget_notes_updated_at"() TO "service_role";

































GRANT ALL ON TABLE "public"."cell_locks" TO "anon";
GRANT ALL ON TABLE "public"."cell_locks" TO "authenticated";
GRANT ALL ON TABLE "public"."cell_locks" TO "service_role";



GRANT ALL ON TABLE "public"."coverage" TO "anon";
GRANT ALL ON TABLE "public"."coverage" TO "authenticated";
GRANT ALL ON TABLE "public"."coverage" TO "service_role";



GRANT ALL ON TABLE "public"."dashboard_configs" TO "anon";
GRANT ALL ON TABLE "public"."dashboard_configs" TO "authenticated";
GRANT ALL ON TABLE "public"."dashboard_configs" TO "service_role";



GRANT ALL ON TABLE "public"."deductibles" TO "anon";
GRANT ALL ON TABLE "public"."deductibles" TO "authenticated";
GRANT ALL ON TABLE "public"."deductibles" TO "service_role";



GRANT ALL ON TABLE "public"."exclusions" TO "anon";
GRANT ALL ON TABLE "public"."exclusions" TO "authenticated";
GRANT ALL ON TABLE "public"."exclusions" TO "service_role";



GRANT ALL ON TABLE "public"."limits" TO "anon";
GRANT ALL ON TABLE "public"."limits" TO "authenticated";
GRANT ALL ON TABLE "public"."limits" TO "service_role";



GRANT ALL ON TABLE "public"."location_snapshots" TO "anon";
GRANT ALL ON TABLE "public"."location_snapshots" TO "authenticated";
GRANT ALL ON TABLE "public"."location_snapshots" TO "service_role";



GRANT ALL ON TABLE "public"."loss" TO "anon";
GRANT ALL ON TABLE "public"."loss" TO "authenticated";
GRANT ALL ON TABLE "public"."loss" TO "service_role";



GRANT ALL ON TABLE "public"."loss_automotive_specific" TO "anon";
GRANT ALL ON TABLE "public"."loss_automotive_specific" TO "authenticated";
GRANT ALL ON TABLE "public"."loss_automotive_specific" TO "service_role";



GRANT ALL ON TABLE "public"."loss_event" TO "anon";
GRANT ALL ON TABLE "public"."loss_event" TO "authenticated";
GRANT ALL ON TABLE "public"."loss_event" TO "service_role";



GRANT ALL ON TABLE "public"."loss_machine_liability_specific" TO "anon";
GRANT ALL ON TABLE "public"."loss_machine_liability_specific" TO "authenticated";
GRANT ALL ON TABLE "public"."loss_machine_liability_specific" TO "service_role";



GRANT ALL ON TABLE "public"."physical_location" TO "anon";
GRANT ALL ON TABLE "public"."physical_location" TO "authenticated";
GRANT ALL ON TABLE "public"."physical_location" TO "service_role";



GRANT ALL ON TABLE "public"."policy" TO "anon";
GRANT ALL ON TABLE "public"."policy" TO "authenticated";
GRANT ALL ON TABLE "public"."policy" TO "service_role";



GRANT ALL ON TABLE "public"."policy_layer" TO "anon";
GRANT ALL ON TABLE "public"."policy_layer" TO "authenticated";
GRANT ALL ON TABLE "public"."policy_layer" TO "service_role";



GRANT ALL ON TABLE "public"."policy_premium" TO "anon";
GRANT ALL ON TABLE "public"."policy_premium" TO "authenticated";
GRANT ALL ON TABLE "public"."policy_premium" TO "service_role";



GRANT ALL ON TABLE "public"."portfolio_shares" TO "anon";
GRANT ALL ON TABLE "public"."portfolio_shares" TO "authenticated";
GRANT ALL ON TABLE "public"."portfolio_shares" TO "service_role";



GRANT ALL ON TABLE "public"."portfolio_snapshots" TO "anon";
GRANT ALL ON TABLE "public"."portfolio_snapshots" TO "authenticated";
GRANT ALL ON TABLE "public"."portfolio_snapshots" TO "service_role";



GRANT ALL ON TABLE "public"."postal_address" TO "anon";
GRANT ALL ON TABLE "public"."postal_address" TO "authenticated";
GRANT ALL ON TABLE "public"."postal_address" TO "service_role";



GRANT ALL ON TABLE "public"."risk_object" TO "anon";
GRANT ALL ON TABLE "public"."risk_object" TO "authenticated";
GRANT ALL ON TABLE "public"."risk_object" TO "service_role";



GRANT ALL ON TABLE "public"."risk_object_event" TO "anon";
GRANT ALL ON TABLE "public"."risk_object_event" TO "authenticated";
GRANT ALL ON TABLE "public"."risk_object_event" TO "service_role";



GRANT ALL ON TABLE "public"."risk_object_peril_distribution" TO "anon";
GRANT ALL ON TABLE "public"."risk_object_peril_distribution" TO "authenticated";
GRANT ALL ON TABLE "public"."risk_object_peril_distribution" TO "service_role";



GRANT ALL ON TABLE "public"."risk_object_portfolio" TO "anon";
GRANT ALL ON TABLE "public"."risk_object_portfolio" TO "authenticated";
GRANT ALL ON TABLE "public"."risk_object_portfolio" TO "service_role";



GRANT ALL ON TABLE "public"."risk_object_property" TO "anon";
GRANT ALL ON TABLE "public"."risk_object_property" TO "authenticated";
GRANT ALL ON TABLE "public"."risk_object_property" TO "service_role";



GRANT ALL ON TABLE "public"."risk_object_task" TO "anon";
GRANT ALL ON TABLE "public"."risk_object_task" TO "authenticated";
GRANT ALL ON TABLE "public"."risk_object_task" TO "service_role";



GRANT ALL ON TABLE "public"."team_members" TO "anon";
GRANT ALL ON TABLE "public"."team_members" TO "authenticated";
GRANT ALL ON TABLE "public"."team_members" TO "service_role";



GRANT ALL ON TABLE "public"."team_risk_objects" TO "anon";
GRANT ALL ON TABLE "public"."team_risk_objects" TO "authenticated";
GRANT ALL ON TABLE "public"."team_risk_objects" TO "service_role";



GRANT ALL ON TABLE "public"."teams" TO "anon";
GRANT ALL ON TABLE "public"."teams" TO "authenticated";
GRANT ALL ON TABLE "public"."teams" TO "service_role";



GRANT ALL ON TABLE "public"."widget_notes" TO "anon";
GRANT ALL ON TABLE "public"."widget_notes" TO "authenticated";
GRANT ALL ON TABLE "public"."widget_notes" TO "service_role";









ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "service_role";



































drop extension if exists "pg_net";


