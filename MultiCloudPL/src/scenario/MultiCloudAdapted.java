package scenario;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.chocosolver.solver.ResolutionPolicy;
import org.chocosolver.solver.Solver;
import org.chocosolver.solver.constraints.Constraint;
import org.chocosolver.solver.constraints.IntConstraintFactory;
import org.chocosolver.solver.constraints.LogicalConstraintFactory;
import org.chocosolver.solver.constraints.SatFactory;
import org.chocosolver.solver.constraints.nary.cnf.LogOp;
import org.chocosolver.solver.search.loop.monitors.SMF;
import org.chocosolver.solver.search.strategy.IntStrategyFactory;
import org.chocosolver.solver.search.strategy.strategy.IntStrategy;
import org.chocosolver.solver.trace.Chatterbox;
import org.chocosolver.solver.variables.BoolVar;
import org.chocosolver.solver.variables.IntVar;
import org.chocosolver.solver.variables.Variable;
import org.chocosolver.solver.variables.VariableFactory;

public class MultiCloudAdapted {
	private static Solver solver;
	private static BoolVar cl_cloud;
	private static BoolVar cl_authentication;
	private static BoolVar cl_auth_saml;
	private static BoolVar cl_auth_oauth;
	private static BoolVar cl_auth_pki;
	private static BoolVar cl_auth_otp;
	private static BoolVar cl_auth_otp_sms;
	private static BoolVar cl_auth_otp_email;
	private static BoolVar cl_auth_push;
	private static BoolVar cl_auth_token;
	private static BoolVar cl_auth_token_hard;
	private static BoolVar cl_auth_token_soft;
	private static BoolVar cld_auth_qrcode;
	private static BoolVar cl_compute;
	private static BoolVar cl_compute_osinstances;
	private static BoolVar cl_compute_osinstances_windows;
	private static BoolVar cl_compute_osinstances_linux;
	private static BoolVar cl_compute_osinstances_linux_ubuntu;
	private static BoolVar cl_compute_osinstances_linux_debian;
	private static BoolVar cl_compute_osinstances_linux_redhat;
	private static BoolVar cl_compute_osinstances_linux_fedora;
	private static BoolVar cl_compute_osinstances_linux_suse;
	private static BoolVar cl_compute_appplatform;
	private static BoolVar cl_compute_containers;
	private static BoolVar cl_compute_autoscaling;
	private static BoolVar cl_storage;
	private static BoolVar cl_storage_block;
	private static BoolVar cl_storage_block_hdd;
	private static BoolVar cl_storage_block_ssd;
	private static BoolVar cl_storage_object;
	private static BoolVar cl_storage_cache;
	private static BoolVar cl_storage_cache_engine;
	private static BoolVar cl_storage_cache_memcache;
	private static BoolVar cl_storage_cache_memcached;
	private static BoolVar cl_storage_cache_redis;
	private static BoolVar cl_storage_database;
	private static BoolVar cl_storage_db_engine;
	private static BoolVar cl_storage_database_dbengine_sql;
	private static BoolVar cl_storage_database_dbengine_sql_posgresql;
	private static BoolVar cl_storage_database_dbengine_sql_mysql;
	private static BoolVar cl_storage_database_dbengine_sql_sqlserver;
	private static BoolVar cl_storage_database_dbengine_sql_oracle;
	private static BoolVar cl_storage_database_dbengine_nosql;
	private static BoolVar cl_signature;
	private static BoolVar cl_messaging;
	private static BoolVar cl_messaging_queues;
	private static BoolVar cl_messaging_notification;
	private static BoolVar cl_messaging_mailing;
	private static BoolVar cl_network;
	private static BoolVar cl_networking_cdn;
	private static BoolVar cl_networking_dns;
	private static BoolVar cl_networking_loadbalancing;
	private static BoolVar cl_monitoring;
	private static BoolVar cl_audit;
	private static BoolVar cl_aws;
	private static BoolVar cl_aws_compute;
	private static BoolVar cl_aws_compute_ec2;
	private static BoolVar cl_aws_compute_ec2_windows;
	private static BoolVar cl_compute_ec2_linux;
	private static BoolVar cl_aws_compute_lambda;
	private static BoolVar cl_aws_compute_container_service;
	private static BoolVar cl_aws_storage;
	private static BoolVar cl_aws_storage_s3;
	private static BoolVar cl_aws_storage_ebs;
	private static BoolVar cl_aws_storage_ebs_ssd;
	private static BoolVar cl_aws_storage_ebs_magnetic;
	private static BoolVar cl_aws_storage_glacier;
	private static BoolVar cl_aws_database;
	private static BoolVar cl_aws_database_aurora;
	private static BoolVar cl_aws_storage_rds;
	private static BoolVar cl_aws_database_posgresql;
	private static BoolVar cl_aws_database_rds_mysql;
	private static BoolVar cl_aws_database_rds_sqlserver;
	private static BoolVar cl_aws_database_rds_oracle;
	private static BoolVar cl_aws_messaging;
	private static BoolVar cl_aws_messaging_ses;
	private static BoolVar cl_aws_messaging_sns;
	private static BoolVar cl_aws_networking;
	private static BoolVar cl_aws_networking_cloudfront;
	private static BoolVar cl_aws_networking_route53;
	private static BoolVar cl_aws_networking_elb;
	private static BoolVar cl_aws_authentication;
	private static BoolVar cl_gcp;
	private static BoolVar cl_gcp_compute;
	private static BoolVar cl_gcp_compute_computeengine;
	private static BoolVar cl_gcp_compute_appengine;
	private static BoolVar cl_gcp_compute_containerengine;
	private static BoolVar cl_gcp_storage;
	private static BoolVar cl_gcp_storage_object;
	private static BoolVar cl_gcp_database;
	private static BoolVar cl_gcp_database_nosql;
	private static BoolVar cl_gcp_database_nosql_datastore;
	private static BoolVar cl_gcp_database_bigtable;
	private static BoolVar cl_gcp_storage_database_cloudsql;
	private static BoolVar cl_gcp_storage_cloudstorage;
	private static BoolVar cl_gcp_storage_standard;
	private static BoolVar cl_gcp_storage_nearline;
	private static BoolVar cl_gcp_storage_coldline;
	private static BoolVar cl_gcp_storage_bigtable;
	private static BoolVar cl_gcp_networking;
	private static BoolVar cl_gcp_cdn;
	private static BoolVar cl_gcp_dns;
	private static BoolVar cl_gcp_loadbalancing;
	private static BoolVar cl_gcp_authentication;
	private static BoolVar cl_gcp_authentication_iam;
	private static BoolVar cl_gcp_bigdata;
	private static BoolVar cl_gcp_bigdata_pubsub;
	private static HashMap<String, IntVar> featureAttrsla;
	private static HashMap<String, IntVar> featureAttrauditability;
	private static HashMap<String, IntVar> featureAttrcompliance;
	private static HashMap<String, IntVar> featureAttrease_of_doing_business;
	private static HashMap<String, IntVar> featureAttrownership;
	private static HashMap<String, IntVar> featureAttrprovider_business_stability;
	private static HashMap<String, IntVar> featureAttrprovider_support;
	private static HashMap<String, IntVar> featureAttrelasticity;
	private static HashMap<String, IntVar> featureAttrportability;
	private static HashMap<String, IntVar> featureAttrscalabilty;
	private static HashMap<String, IntVar> featureAttrinteroperability;
	private static HashMap<String, IntVar> featureAttrlearnalability;

	public static void main(String[] args) {
		solver = new Solver();
		
		//--------------------------------------------
		//Features
		//--------------------------------------------
		initializeVars();

		//--------------------------------------------
		//Feature Attributes
		//--------------------------------------------
		initializeFeatureAttributes();

		//--------------------------------------------
		//Tree Constraints
		//--------------------------------------------
		Constraint optionalcl_cloud_cl_authentication = IntConstraintFactory.arithm(cl_authentication, "<=", cl_cloud);
		optionalcl_cloud_cl_authentication.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_cloud_cl_authentication);
		Constraint optionalcl_cloud_cl_compute = IntConstraintFactory.arithm(cl_compute, "<=", cl_cloud);
		optionalcl_cloud_cl_compute.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_cloud_cl_compute);
		Constraint optionalcl_cloud_cl_storage = IntConstraintFactory.arithm(cl_storage, "<=", cl_cloud);
		optionalcl_cloud_cl_storage.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_cloud_cl_storage);
		Constraint optionalcl_cloud_cl_signature = IntConstraintFactory.arithm(cl_signature, "<=", cl_cloud);
		optionalcl_cloud_cl_signature.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_cloud_cl_signature);
		Constraint optionalcl_cloud_cl_messaging = IntConstraintFactory.arithm(cl_messaging, "<=", cl_cloud);
		optionalcl_cloud_cl_messaging.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_cloud_cl_messaging);
		Constraint optionalcl_cloud_cl_network = IntConstraintFactory.arithm(cl_network, "<=", cl_cloud);
		optionalcl_cloud_cl_network.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_cloud_cl_network);
		Constraint optionalcl_cloud_cl_monitoring = IntConstraintFactory.arithm(cl_monitoring, "<=", cl_cloud);
		optionalcl_cloud_cl_monitoring.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_cloud_cl_monitoring);
		Constraint optionalcl_cloud_cl_audit = IntConstraintFactory.arithm(cl_audit, "<=", cl_cloud);
		optionalcl_cloud_cl_audit.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_cloud_cl_audit);
		IntVar sumOrcl_authentication_0 = VariableFactory.enumerated("sumOrcl_authentication", 0, 7, solver); 
		BoolVar[] varsOrcl_authentication_0 = new BoolVar[7];
		varsOrcl_authentication_0[0] = cl_auth_saml;
		varsOrcl_authentication_0[1] = cl_auth_oauth;
		varsOrcl_authentication_0[2] = cl_auth_pki;
		varsOrcl_authentication_0[3] = cl_auth_otp;
		varsOrcl_authentication_0[4] = cl_auth_push;
		varsOrcl_authentication_0[5] = cl_auth_token;
		varsOrcl_authentication_0[6] = cld_auth_qrcode;
		solver.post(IntConstraintFactory.sum(varsOrcl_authentication_0, sumOrcl_authentication_0));
		Constraint or1cl_authentication_0 = IntConstraintFactory.arithm(sumOrcl_authentication_0, ">=", 1);
		or1cl_authentication_0.setName(Utilities.OR_TC);

		Constraint or0cl_authentication_0 = IntConstraintFactory.arithm(sumOrcl_authentication_0, "=", 0);
		or0cl_authentication_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_authentication, or1cl_authentication_0, or0cl_authentication_0);

		IntVar sumOrcl_auth_otp_0 = VariableFactory.enumerated("sumOrcl_auth_otp", 0, 2, solver); 
		BoolVar[] varsOrcl_auth_otp_0 = new BoolVar[2];
		varsOrcl_auth_otp_0[0] = cl_auth_otp_sms;
		varsOrcl_auth_otp_0[1] = cl_auth_otp_email;
		solver.post(IntConstraintFactory.sum(varsOrcl_auth_otp_0, sumOrcl_auth_otp_0));
		Constraint or1cl_auth_otp_0 = IntConstraintFactory.arithm(sumOrcl_auth_otp_0, ">=", 1);
		or1cl_auth_otp_0.setName(Utilities.OR_TC);

		Constraint or0cl_auth_otp_0 = IntConstraintFactory.arithm(sumOrcl_auth_otp_0, "=", 0);
		or0cl_auth_otp_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_auth_otp, or1cl_auth_otp_0, or0cl_auth_otp_0);

		IntVar sumOrcl_auth_token_0 = VariableFactory.enumerated("sumOrcl_auth_token", 0, 2, solver); 
		BoolVar[] varsOrcl_auth_token_0 = new BoolVar[2];
		varsOrcl_auth_token_0[0] = cl_auth_token_hard;
		varsOrcl_auth_token_0[1] = cl_auth_token_soft;
		solver.post(IntConstraintFactory.sum(varsOrcl_auth_token_0, sumOrcl_auth_token_0));
		Constraint or1cl_auth_token_0 = IntConstraintFactory.arithm(sumOrcl_auth_token_0, ">=", 1);
		or1cl_auth_token_0.setName(Utilities.OR_TC);

		Constraint or0cl_auth_token_0 = IntConstraintFactory.arithm(sumOrcl_auth_token_0, "=", 0);
		or0cl_auth_token_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_auth_token, or1cl_auth_token_0, or0cl_auth_token_0);

		IntVar sumOrcl_compute_0 = VariableFactory.enumerated("sumOrcl_compute", 0, 4, solver); 
		BoolVar[] varsOrcl_compute_0 = new BoolVar[4];
		varsOrcl_compute_0[0] = cl_compute_osinstances;
		varsOrcl_compute_0[1] = cl_compute_appplatform;
		varsOrcl_compute_0[2] = cl_compute_containers;
		varsOrcl_compute_0[3] = cl_compute_autoscaling;
		solver.post(IntConstraintFactory.sum(varsOrcl_compute_0, sumOrcl_compute_0));
		Constraint or1cl_compute_0 = IntConstraintFactory.arithm(sumOrcl_compute_0, ">=", 1);
		or1cl_compute_0.setName(Utilities.OR_TC);

		Constraint or0cl_compute_0 = IntConstraintFactory.arithm(sumOrcl_compute_0, "=", 0);
		or0cl_compute_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_compute, or1cl_compute_0, or0cl_compute_0);

		IntVar sumOrcl_compute_osinstances_0 = VariableFactory.enumerated("sumOrcl_compute_osinstances", 0, 2, solver); 
		BoolVar[] varsOrcl_compute_osinstances_0 = new BoolVar[2];
		varsOrcl_compute_osinstances_0[0] = cl_compute_osinstances_windows;
		varsOrcl_compute_osinstances_0[1] = cl_compute_osinstances_linux;
		solver.post(IntConstraintFactory.sum(varsOrcl_compute_osinstances_0, sumOrcl_compute_osinstances_0));
		Constraint or1cl_compute_osinstances_0 = IntConstraintFactory.arithm(sumOrcl_compute_osinstances_0, ">=", 1);
		or1cl_compute_osinstances_0.setName(Utilities.OR_TC);

		Constraint or0cl_compute_osinstances_0 = IntConstraintFactory.arithm(sumOrcl_compute_osinstances_0, "=", 0);
		or0cl_compute_osinstances_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_compute_osinstances, or1cl_compute_osinstances_0, or0cl_compute_osinstances_0);

		IntVar sumOrcl_compute_osinstances_linux_0 = VariableFactory.enumerated("sumOrcl_compute_osinstances_linux", 0, 5, solver); 
		BoolVar[] varsOrcl_compute_osinstances_linux_0 = new BoolVar[5];
		varsOrcl_compute_osinstances_linux_0[0] = cl_compute_osinstances_linux_ubuntu;
		varsOrcl_compute_osinstances_linux_0[1] = cl_compute_osinstances_linux_debian;
		varsOrcl_compute_osinstances_linux_0[2] = cl_compute_osinstances_linux_redhat;
		varsOrcl_compute_osinstances_linux_0[3] = cl_compute_osinstances_linux_fedora;
		varsOrcl_compute_osinstances_linux_0[4] = cl_compute_osinstances_linux_suse;
		solver.post(IntConstraintFactory.sum(varsOrcl_compute_osinstances_linux_0, sumOrcl_compute_osinstances_linux_0));
		Constraint or1cl_compute_osinstances_linux_0 = IntConstraintFactory.arithm(sumOrcl_compute_osinstances_linux_0, ">=", 1);
		or1cl_compute_osinstances_linux_0.setName(Utilities.OR_TC);

		Constraint or0cl_compute_osinstances_linux_0 = IntConstraintFactory.arithm(sumOrcl_compute_osinstances_linux_0, "=", 0);
		or0cl_compute_osinstances_linux_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_compute_osinstances_linux, or1cl_compute_osinstances_linux_0, or0cl_compute_osinstances_linux_0);

		IntVar sumOrcl_storage_0 = VariableFactory.enumerated("sumOrcl_storage", 0, 4, solver); 
		BoolVar[] varsOrcl_storage_0 = new BoolVar[4];
		varsOrcl_storage_0[0] = cl_storage_block;
		varsOrcl_storage_0[1] = cl_storage_object;
		varsOrcl_storage_0[2] = cl_storage_cache;
		varsOrcl_storage_0[3] = cl_storage_database;
		solver.post(IntConstraintFactory.sum(varsOrcl_storage_0, sumOrcl_storage_0));
		Constraint or1cl_storage_0 = IntConstraintFactory.arithm(sumOrcl_storage_0, ">=", 1);
		or1cl_storage_0.setName(Utilities.OR_TC);

		Constraint or0cl_storage_0 = IntConstraintFactory.arithm(sumOrcl_storage_0, "=", 0);
		or0cl_storage_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_storage, or1cl_storage_0, or0cl_storage_0);

		IntVar sumOrcl_storage_block_0 = VariableFactory.enumerated("sumOrcl_storage_block", 0, 2, solver); 
		BoolVar[] varsOrcl_storage_block_0 = new BoolVar[2];
		varsOrcl_storage_block_0[0] = cl_storage_block_hdd;
		varsOrcl_storage_block_0[1] = cl_storage_block_ssd;
		solver.post(IntConstraintFactory.sum(varsOrcl_storage_block_0, sumOrcl_storage_block_0));
		Constraint or1cl_storage_block_0 = IntConstraintFactory.arithm(sumOrcl_storage_block_0, ">=", 1);
		or1cl_storage_block_0.setName(Utilities.OR_TC);

		Constraint or0cl_storage_block_0 = IntConstraintFactory.arithm(sumOrcl_storage_block_0, "=", 0);
		or0cl_storage_block_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_storage_block, or1cl_storage_block_0, or0cl_storage_block_0);

		IntVar sumXorcl_storage_cache_0 = VariableFactory.fixed("sumXorcl_storage_cache", 1, solver);
		BoolVar[] varsXorcl_storage_cache_0 = new BoolVar[1];
		varsXorcl_storage_cache_0[0] = cl_storage_cache_engine;
		solver.post(IntConstraintFactory.sum(varsXorcl_storage_cache_0, sumXorcl_storage_cache_0));
		Constraint xor1cl_storage_cache_0 = IntConstraintFactory.arithm(sumXorcl_storage_cache_0, "=", 1);
		xor1cl_storage_cache_0.setName(Utilities.XOR_TC);

		Constraint xor0cl_storage_cache_0 = IntConstraintFactory.arithm(sumXorcl_storage_cache_0, "=", 0);
		xor0cl_storage_cache_0.setName(Utilities.XOR_TC);

		LogicalConstraintFactory.ifThenElse(cl_storage_cache, xor1cl_storage_cache_0, xor0cl_storage_cache_0);

		IntVar sumOrcl_storage_cache_engine_0 = VariableFactory.enumerated("sumOrcl_storage_cache_engine", 0, 3, solver); 
		BoolVar[] varsOrcl_storage_cache_engine_0 = new BoolVar[3];
		varsOrcl_storage_cache_engine_0[0] = cl_storage_cache_memcache;
		varsOrcl_storage_cache_engine_0[1] = cl_storage_cache_memcached;
		varsOrcl_storage_cache_engine_0[2] = cl_storage_cache_redis;
		solver.post(IntConstraintFactory.sum(varsOrcl_storage_cache_engine_0, sumOrcl_storage_cache_engine_0));
		Constraint or1cl_storage_cache_engine_0 = IntConstraintFactory.arithm(sumOrcl_storage_cache_engine_0, ">=", 1);
		or1cl_storage_cache_engine_0.setName(Utilities.OR_TC);

		Constraint or0cl_storage_cache_engine_0 = IntConstraintFactory.arithm(sumOrcl_storage_cache_engine_0, "=", 0);
		or0cl_storage_cache_engine_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_storage_cache_engine, or1cl_storage_cache_engine_0, or0cl_storage_cache_engine_0);

		Constraint optionalcl_storage_database_cl_storage_db_engine = IntConstraintFactory.arithm(cl_storage_db_engine, "<=", cl_storage_database);
		optionalcl_storage_database_cl_storage_db_engine.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_storage_database_cl_storage_db_engine);
		IntVar sumOrcl_storage_db_engine_0 = VariableFactory.enumerated("sumOrcl_storage_db_engine", 0, 2, solver); 
		BoolVar[] varsOrcl_storage_db_engine_0 = new BoolVar[2];
		varsOrcl_storage_db_engine_0[0] = cl_storage_database_dbengine_sql;
		varsOrcl_storage_db_engine_0[1] = cl_storage_database_dbengine_nosql;
		solver.post(IntConstraintFactory.sum(varsOrcl_storage_db_engine_0, sumOrcl_storage_db_engine_0));
		Constraint or1cl_storage_db_engine_0 = IntConstraintFactory.arithm(sumOrcl_storage_db_engine_0, ">=", 1);
		or1cl_storage_db_engine_0.setName(Utilities.OR_TC);

		Constraint or0cl_storage_db_engine_0 = IntConstraintFactory.arithm(sumOrcl_storage_db_engine_0, "=", 0);
		or0cl_storage_db_engine_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_storage_db_engine, or1cl_storage_db_engine_0, or0cl_storage_db_engine_0);

		IntVar sumOrcl_storage_database_dbengine_sql_0 = VariableFactory.enumerated("sumOrcl_storage_database_dbengine_sql", 0, 4, solver); 
		BoolVar[] varsOrcl_storage_database_dbengine_sql_0 = new BoolVar[4];
		varsOrcl_storage_database_dbengine_sql_0[0] = cl_storage_database_dbengine_sql_posgresql;
		varsOrcl_storage_database_dbengine_sql_0[1] = cl_storage_database_dbengine_sql_mysql;
		varsOrcl_storage_database_dbengine_sql_0[2] = cl_storage_database_dbengine_sql_sqlserver;
		varsOrcl_storage_database_dbengine_sql_0[3] = cl_storage_database_dbengine_sql_oracle;
		solver.post(IntConstraintFactory.sum(varsOrcl_storage_database_dbengine_sql_0, sumOrcl_storage_database_dbengine_sql_0));
		Constraint or1cl_storage_database_dbengine_sql_0 = IntConstraintFactory.arithm(sumOrcl_storage_database_dbengine_sql_0, ">=", 1);
		or1cl_storage_database_dbengine_sql_0.setName(Utilities.OR_TC);

		Constraint or0cl_storage_database_dbengine_sql_0 = IntConstraintFactory.arithm(sumOrcl_storage_database_dbengine_sql_0, "=", 0);
		or0cl_storage_database_dbengine_sql_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_storage_database_dbengine_sql, or1cl_storage_database_dbengine_sql_0, or0cl_storage_database_dbengine_sql_0);

		IntVar sumOrcl_messaging_0 = VariableFactory.enumerated("sumOrcl_messaging", 0, 3, solver); 
		BoolVar[] varsOrcl_messaging_0 = new BoolVar[3];
		varsOrcl_messaging_0[0] = cl_messaging_queues;
		varsOrcl_messaging_0[1] = cl_messaging_notification;
		varsOrcl_messaging_0[2] = cl_messaging_mailing;
		solver.post(IntConstraintFactory.sum(varsOrcl_messaging_0, sumOrcl_messaging_0));
		Constraint or1cl_messaging_0 = IntConstraintFactory.arithm(sumOrcl_messaging_0, ">=", 1);
		or1cl_messaging_0.setName(Utilities.OR_TC);

		Constraint or0cl_messaging_0 = IntConstraintFactory.arithm(sumOrcl_messaging_0, "=", 0);
		or0cl_messaging_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_messaging, or1cl_messaging_0, or0cl_messaging_0);

		IntVar sumOrcl_network_0 = VariableFactory.enumerated("sumOrcl_network", 0, 3, solver); 
		BoolVar[] varsOrcl_network_0 = new BoolVar[3];
		varsOrcl_network_0[0] = cl_networking_cdn;
		varsOrcl_network_0[1] = cl_networking_dns;
		varsOrcl_network_0[2] = cl_networking_loadbalancing;
		solver.post(IntConstraintFactory.sum(varsOrcl_network_0, sumOrcl_network_0));
		Constraint or1cl_network_0 = IntConstraintFactory.arithm(sumOrcl_network_0, ">=", 1);
		or1cl_network_0.setName(Utilities.OR_TC);

		Constraint or0cl_network_0 = IntConstraintFactory.arithm(sumOrcl_network_0, "=", 0);
		or0cl_network_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_network, or1cl_network_0, or0cl_network_0);

		Constraint optionalcl_aws_cl_aws_compute = IntConstraintFactory.arithm(cl_aws_compute, "<=", cl_aws);
		optionalcl_aws_cl_aws_compute.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_aws_cl_aws_compute);
		Constraint optionalcl_aws_cl_aws_storage = IntConstraintFactory.arithm(cl_aws_storage, "<=", cl_aws);
		optionalcl_aws_cl_aws_storage.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_aws_cl_aws_storage);
		Constraint optionalcl_aws_cl_aws_database = IntConstraintFactory.arithm(cl_aws_database, "<=", cl_aws);
		optionalcl_aws_cl_aws_database.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_aws_cl_aws_database);
		Constraint optionalcl_aws_cl_aws_messaging = IntConstraintFactory.arithm(cl_aws_messaging, "<=", cl_aws);
		optionalcl_aws_cl_aws_messaging.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_aws_cl_aws_messaging);
		Constraint mandatorycl_aws_cl_aws_networking = IntConstraintFactory.arithm(cl_aws, "=", cl_aws_networking);
		mandatorycl_aws_cl_aws_networking.setName(Utilities.MANDATORY_TC);
		solver.post(mandatorycl_aws_cl_aws_networking);
		Constraint optionalcl_aws_cl_aws_authentication = IntConstraintFactory.arithm(cl_aws_authentication, "<=", cl_aws);
		optionalcl_aws_cl_aws_authentication.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_aws_cl_aws_authentication);
		Constraint mandatorycl_aws_compute_cl_aws_compute_ec2 = IntConstraintFactory.arithm(cl_aws_compute, "=", cl_aws_compute_ec2);
		mandatorycl_aws_compute_cl_aws_compute_ec2.setName(Utilities.MANDATORY_TC);
		solver.post(mandatorycl_aws_compute_cl_aws_compute_ec2);
		Constraint optionalcl_aws_compute_cl_aws_compute_lambda = IntConstraintFactory.arithm(cl_aws_compute_lambda, "<=", cl_aws_compute);
		optionalcl_aws_compute_cl_aws_compute_lambda.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_aws_compute_cl_aws_compute_lambda);
		Constraint optionalcl_aws_compute_cl_aws_compute_container_service = IntConstraintFactory.arithm(cl_aws_compute_container_service, "<=", cl_aws_compute);
		optionalcl_aws_compute_cl_aws_compute_container_service.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_aws_compute_cl_aws_compute_container_service);
		
		IntVar sumOrcl_aws_storage_0 = VariableFactory.enumerated("sumOrcl_aws_storage", 0, 3, solver); 
		BoolVar[] varsOrcl_aws_storage_0 = new BoolVar[3];
		varsOrcl_aws_storage_0[0] = cl_aws_storage_s3;
		varsOrcl_aws_storage_0[1] = cl_aws_storage_ebs;
		varsOrcl_aws_storage_0[2] = cl_aws_storage_glacier;
		solver.post(IntConstraintFactory.sum(varsOrcl_aws_storage_0, sumOrcl_aws_storage_0));
		Constraint or1cl_aws_storage_0 = IntConstraintFactory.arithm(sumOrcl_aws_storage_0, ">=", 1);
		or1cl_aws_storage_0.setName(Utilities.OR_TC);

		Constraint or0cl_aws_storage_0 = IntConstraintFactory.arithm(sumOrcl_aws_storage_0, "=", 0);
		or0cl_aws_storage_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_aws_storage, or1cl_aws_storage_0, or0cl_aws_storage_0);

		IntVar sumXorcl_aws_storage_ebs_0 = VariableFactory.fixed("sumXorcl_aws_storage_ebs", 1, solver);
		BoolVar[] varsXorcl_aws_storage_ebs_0 = new BoolVar[2];
		varsXorcl_aws_storage_ebs_0[0] = cl_aws_storage_ebs_ssd;
		varsXorcl_aws_storage_ebs_0[1] = cl_aws_storage_ebs_magnetic;
		solver.post(IntConstraintFactory.sum(varsXorcl_aws_storage_ebs_0, sumXorcl_aws_storage_ebs_0));
		Constraint xor1cl_aws_storage_ebs_0 = IntConstraintFactory.arithm(sumXorcl_aws_storage_ebs_0, "=", 1);
		xor1cl_aws_storage_ebs_0.setName(Utilities.XOR_TC);

		Constraint xor0cl_aws_storage_ebs_0 = IntConstraintFactory.arithm(sumXorcl_aws_storage_ebs_0, "=", 0);
		xor0cl_aws_storage_ebs_0.setName(Utilities.XOR_TC);

		LogicalConstraintFactory.ifThenElse(cl_aws_storage_ebs, xor1cl_aws_storage_ebs_0, xor0cl_aws_storage_ebs_0);

		IntVar sumOrcl_aws_database_0 = VariableFactory.enumerated("sumOrcl_aws_database", 0, 2, solver); 
		BoolVar[] varsOrcl_aws_database_0 = new BoolVar[2];
		varsOrcl_aws_database_0[0] = cl_aws_database_aurora;
		varsOrcl_aws_database_0[1] = cl_aws_storage_rds;
		solver.post(IntConstraintFactory.sum(varsOrcl_aws_database_0, sumOrcl_aws_database_0));
		Constraint or1cl_aws_database_0 = IntConstraintFactory.arithm(sumOrcl_aws_database_0, ">=", 1);
		or1cl_aws_database_0.setName(Utilities.OR_TC);

		Constraint or0cl_aws_database_0 = IntConstraintFactory.arithm(sumOrcl_aws_database_0, "=", 0);
		or0cl_aws_database_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_aws_database, or1cl_aws_database_0, or0cl_aws_database_0);

		IntVar sumXorcl_aws_storage_rds_0 = VariableFactory.fixed("sumXorcl_aws_storage_rds", 1, solver);
		BoolVar[] varsXorcl_aws_storage_rds_0 = new BoolVar[4];
		varsXorcl_aws_storage_rds_0[0] = cl_aws_database_posgresql;
		varsXorcl_aws_storage_rds_0[1] = cl_aws_database_rds_mysql;
		varsXorcl_aws_storage_rds_0[2] = cl_aws_database_rds_sqlserver;
		varsXorcl_aws_storage_rds_0[3] = cl_aws_database_rds_oracle;
		solver.post(IntConstraintFactory.sum(varsXorcl_aws_storage_rds_0, sumXorcl_aws_storage_rds_0));
		Constraint xor1cl_aws_storage_rds_0 = IntConstraintFactory.arithm(sumXorcl_aws_storage_rds_0, "=", 1);
		xor1cl_aws_storage_rds_0.setName(Utilities.XOR_TC);

		Constraint xor0cl_aws_storage_rds_0 = IntConstraintFactory.arithm(sumXorcl_aws_storage_rds_0, "=", 0);
		xor0cl_aws_storage_rds_0.setName(Utilities.XOR_TC);

		LogicalConstraintFactory.ifThenElse(cl_aws_storage_rds, xor1cl_aws_storage_rds_0, xor0cl_aws_storage_rds_0);

		IntVar sumOrcl_aws_messaging_0 = VariableFactory.enumerated("sumOrcl_aws_messaging", 0, 2, solver); 
		BoolVar[] varsOrcl_aws_messaging_0 = new BoolVar[2];
		varsOrcl_aws_messaging_0[0] = cl_aws_messaging_ses;
		varsOrcl_aws_messaging_0[1] = cl_aws_messaging_sns;
		solver.post(IntConstraintFactory.sum(varsOrcl_aws_messaging_0, sumOrcl_aws_messaging_0));
		Constraint or1cl_aws_messaging_0 = IntConstraintFactory.arithm(sumOrcl_aws_messaging_0, ">=", 1);
		or1cl_aws_messaging_0.setName(Utilities.OR_TC);

		Constraint or0cl_aws_messaging_0 = IntConstraintFactory.arithm(sumOrcl_aws_messaging_0, "=", 0);
		or0cl_aws_messaging_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_aws_messaging, or1cl_aws_messaging_0, or0cl_aws_messaging_0);

		Constraint optionalcl_aws_networking_cl_aws_networking_cloudfront = IntConstraintFactory.arithm(cl_aws_networking_cloudfront, "<=", cl_aws_networking);
		optionalcl_aws_networking_cl_aws_networking_cloudfront.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_aws_networking_cl_aws_networking_cloudfront);
		Constraint optionalcl_aws_networking_cl_aws_networking_route53 = IntConstraintFactory.arithm(cl_aws_networking_route53, "<=", cl_aws_networking);
		optionalcl_aws_networking_cl_aws_networking_route53.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_aws_networking_cl_aws_networking_route53);
		Constraint optionalcl_aws_networking_cl_aws_networking_elb = IntConstraintFactory.arithm(cl_aws_networking_elb, "<=", cl_aws_networking);
		optionalcl_aws_networking_cl_aws_networking_elb.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_aws_networking_cl_aws_networking_elb);
		Constraint mandatorycl_gcp_cl_gcp_compute = IntConstraintFactory.arithm(cl_gcp, "=", cl_gcp_compute);
		mandatorycl_gcp_cl_gcp_compute.setName(Utilities.MANDATORY_TC);
		solver.post(mandatorycl_gcp_cl_gcp_compute);
		Constraint optionalcl_gcp_cl_gcp_storage = IntConstraintFactory.arithm(cl_gcp_storage, "<=", cl_gcp);
		optionalcl_gcp_cl_gcp_storage.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_gcp_cl_gcp_storage);
		Constraint optionalcl_gcp_cl_gcp_networking = IntConstraintFactory.arithm(cl_gcp_networking, "<=", cl_gcp);
		optionalcl_gcp_cl_gcp_networking.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_gcp_cl_gcp_networking);
		Constraint optionalcl_gcp_cl_gcp_authentication = IntConstraintFactory.arithm(cl_gcp_authentication, "<=", cl_gcp);
		optionalcl_gcp_cl_gcp_authentication.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_gcp_cl_gcp_authentication);
		Constraint optionalcl_gcp_cl_gcp_bigdata = IntConstraintFactory.arithm(cl_gcp_bigdata, "<=", cl_gcp);
		optionalcl_gcp_cl_gcp_bigdata.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_gcp_cl_gcp_bigdata);
		IntVar sumOrcl_gcp_compute_0 = VariableFactory.enumerated("sumOrcl_gcp_compute", 0, 3, solver); 
		BoolVar[] varsOrcl_gcp_compute_0 = new BoolVar[3];
		varsOrcl_gcp_compute_0[0] = cl_gcp_compute_computeengine;
		varsOrcl_gcp_compute_0[1] = cl_gcp_compute_appengine;
		varsOrcl_gcp_compute_0[2] = cl_gcp_compute_containerengine;
		solver.post(IntConstraintFactory.sum(varsOrcl_gcp_compute_0, sumOrcl_gcp_compute_0));
		Constraint or1cl_gcp_compute_0 = IntConstraintFactory.arithm(sumOrcl_gcp_compute_0, ">=", 1);
		or1cl_gcp_compute_0.setName(Utilities.OR_TC);

		Constraint or0cl_gcp_compute_0 = IntConstraintFactory.arithm(sumOrcl_gcp_compute_0, "=", 0);
		or0cl_gcp_compute_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_gcp_compute, or1cl_gcp_compute_0, or0cl_gcp_compute_0);

		IntVar sumOrcl_gcp_storage_0 = VariableFactory.enumerated("sumOrcl_gcp_storage", 0, 4, solver); 
		BoolVar[] varsOrcl_gcp_storage_0 = new BoolVar[4];
		varsOrcl_gcp_storage_0[0] = cl_gcp_storage_object;
		varsOrcl_gcp_storage_0[1] = cl_gcp_database;
		varsOrcl_gcp_storage_0[2] = cl_gcp_storage_cloudstorage;
		varsOrcl_gcp_storage_0[3] = cl_gcp_storage_bigtable;
		solver.post(IntConstraintFactory.sum(varsOrcl_gcp_storage_0, sumOrcl_gcp_storage_0));
		Constraint or1cl_gcp_storage_0 = IntConstraintFactory.arithm(sumOrcl_gcp_storage_0, ">=", 1);
		or1cl_gcp_storage_0.setName(Utilities.OR_TC);

		Constraint or0cl_gcp_storage_0 = IntConstraintFactory.arithm(sumOrcl_gcp_storage_0, "=", 0);
		or0cl_gcp_storage_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_gcp_storage, or1cl_gcp_storage_0, or0cl_gcp_storage_0);

		IntVar sumXorcl_gcp_database_0 = VariableFactory.fixed("sumXorcl_gcp_database", 1, solver);
		BoolVar[] varsXorcl_gcp_database_0 = new BoolVar[2];
		varsXorcl_gcp_database_0[0] = cl_gcp_database_nosql;
		varsXorcl_gcp_database_0[1] = cl_gcp_storage_database_cloudsql;
		solver.post(IntConstraintFactory.sum(varsXorcl_gcp_database_0, sumXorcl_gcp_database_0));
		Constraint xor1cl_gcp_database_0 = IntConstraintFactory.arithm(sumXorcl_gcp_database_0, "=", 1);
		xor1cl_gcp_database_0.setName(Utilities.XOR_TC);

		Constraint xor0cl_gcp_database_0 = IntConstraintFactory.arithm(sumXorcl_gcp_database_0, "=", 0);
		xor0cl_gcp_database_0.setName(Utilities.XOR_TC);

		LogicalConstraintFactory.ifThenElse(cl_gcp_database, xor1cl_gcp_database_0, xor0cl_gcp_database_0);

		IntVar sumXorcl_gcp_database_nosql_0 = VariableFactory.fixed("sumXorcl_gcp_database_nosql", 1, solver);
		BoolVar[] varsXorcl_gcp_database_nosql_0 = new BoolVar[2];
		varsXorcl_gcp_database_nosql_0[0] = cl_gcp_database_nosql_datastore;
		varsXorcl_gcp_database_nosql_0[1] = cl_gcp_database_bigtable;
		solver.post(IntConstraintFactory.sum(varsXorcl_gcp_database_nosql_0, sumXorcl_gcp_database_nosql_0));
		Constraint xor1cl_gcp_database_nosql_0 = IntConstraintFactory.arithm(sumXorcl_gcp_database_nosql_0, "=", 1);
		xor1cl_gcp_database_nosql_0.setName(Utilities.XOR_TC);

		Constraint xor0cl_gcp_database_nosql_0 = IntConstraintFactory.arithm(sumXorcl_gcp_database_nosql_0, "=", 0);
		xor0cl_gcp_database_nosql_0.setName(Utilities.XOR_TC);

		LogicalConstraintFactory.ifThenElse(cl_gcp_database_nosql, xor1cl_gcp_database_nosql_0, xor0cl_gcp_database_nosql_0);

		Constraint optionalcl_gcp_storage_cloudstorage_cl_gcp_storage_standard = IntConstraintFactory.arithm(cl_gcp_storage_standard, "<=", cl_gcp_storage_cloudstorage);
		optionalcl_gcp_storage_cloudstorage_cl_gcp_storage_standard.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_gcp_storage_cloudstorage_cl_gcp_storage_standard);
		Constraint optionalcl_gcp_storage_cloudstorage_cl_gcp_storage_nearline = IntConstraintFactory.arithm(cl_gcp_storage_nearline, "<=", cl_gcp_storage_cloudstorage);
		optionalcl_gcp_storage_cloudstorage_cl_gcp_storage_nearline.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_gcp_storage_cloudstorage_cl_gcp_storage_nearline);
		Constraint optionalcl_gcp_storage_cloudstorage_cl_gcp_storage_coldline = IntConstraintFactory.arithm(cl_gcp_storage_coldline, "<=", cl_gcp_storage_cloudstorage);
		optionalcl_gcp_storage_cloudstorage_cl_gcp_storage_coldline.setName(Utilities.OPTIONAL_TC);
		solver.post(optionalcl_gcp_storage_cloudstorage_cl_gcp_storage_coldline);
		IntVar sumOrcl_gcp_networking_0 = VariableFactory.enumerated("sumOrcl_gcp_networking", 0, 3, solver); 
		BoolVar[] varsOrcl_gcp_networking_0 = new BoolVar[3];
		varsOrcl_gcp_networking_0[0] = cl_gcp_cdn;
		varsOrcl_gcp_networking_0[1] = cl_gcp_dns;
		varsOrcl_gcp_networking_0[2] = cl_gcp_loadbalancing;
		solver.post(IntConstraintFactory.sum(varsOrcl_gcp_networking_0, sumOrcl_gcp_networking_0));
		Constraint or1cl_gcp_networking_0 = IntConstraintFactory.arithm(sumOrcl_gcp_networking_0, ">=", 1);
		or1cl_gcp_networking_0.setName(Utilities.OR_TC);

		Constraint or0cl_gcp_networking_0 = IntConstraintFactory.arithm(sumOrcl_gcp_networking_0, "=", 0);
		or0cl_gcp_networking_0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_gcp_networking, or1cl_gcp_networking_0, or0cl_gcp_networking_0);

		Constraint mandatorycl_gcp_authentication_cl_gcp_authentication_iam = IntConstraintFactory.arithm(cl_gcp_authentication, "=", cl_gcp_authentication_iam);
		mandatorycl_gcp_authentication_cl_gcp_authentication_iam.setName(Utilities.MANDATORY_TC);
		solver.post(mandatorycl_gcp_authentication_cl_gcp_authentication_iam);
		Constraint mandatorycl_gcp_bigdata_cl_gcp_bigdata_pubsub = IntConstraintFactory.arithm(cl_gcp_bigdata, "=", cl_gcp_bigdata_pubsub);
		mandatorycl_gcp_bigdata_cl_gcp_bigdata_pubsub.setName(Utilities.MANDATORY_TC);
		solver.post(mandatorycl_gcp_bigdata_cl_gcp_bigdata_pubsub);

		//--------------------------------------------
		//Cross-Tree Constraints
		//--------------------------------------------
		Constraint requirescl_signature_cl_compute = IntConstraintFactory.arithm(cl_signature, "<=", cl_compute);
		requirescl_signature_cl_compute.setName(Utilities.REQUIRES_CTC);
		solver.post(requirescl_signature_cl_compute);
		Constraint requirescl_signature_cl_storage = IntConstraintFactory.arithm(cl_signature, "<=", cl_storage);
		requirescl_signature_cl_storage.setName(Utilities.REQUIRES_CTC);
		solver.post(requirescl_signature_cl_storage);
		Constraint requirescl_signature_cl_authentication = IntConstraintFactory.arithm(cl_signature, "<=", cl_authentication);
		requirescl_signature_cl_authentication.setName(Utilities.REQUIRES_CTC);
		solver.post(requirescl_signature_cl_authentication);
		Constraint requirescl_signature_cl_audit = IntConstraintFactory.arithm(cl_signature, "<=", cl_audit);
		requirescl_signature_cl_audit.setName(Utilities.REQUIRES_CTC);
		solver.post(requirescl_signature_cl_audit);
		Constraint requirescl_compute_cl_authentication = IntConstraintFactory.arithm(cl_compute, "<=", cl_authentication);
		requirescl_compute_cl_authentication.setName(Utilities.REQUIRES_CTC);
		solver.post(requirescl_compute_cl_authentication);
		Constraint requirescl_audit_cl_compute = IntConstraintFactory.arithm(cl_audit, "<=", cl_compute);
		requirescl_audit_cl_compute.setName(Utilities.REQUIRES_CTC);
		solver.post(requirescl_audit_cl_compute);

		//--------------------------------------------
		//Cross-Model Constraints
		//--------------------------------------------
		
		IntVar sum_cmc0 = VariableFactory.enumerated("sum_cmc0", 0, 1, solver); 
		BoolVar[] varsOr_cmc0 = new BoolVar[2];
		varsOr_cmc0[0] = cl_gcp_authentication_iam;
		varsOr_cmc0[1] = cl_aws_authentication;
		solver.post(IntConstraintFactory.sum(varsOr_cmc0, sum_cmc0));
		Constraint or1_cmc0 = IntConstraintFactory.arithm(sum_cmc0, "=", 1);
		or1_cmc0.setName(Utilities.OR_TC);

		Constraint or0_cmc0 = IntConstraintFactory.arithm(sum_cmc0, "=", 0);
		or0_cmc0.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_authentication, or1_cmc0, or0_cmc0);
		
		IntVar sum_cmc1 = VariableFactory.enumerated("sum_cmc1", 0, 1, solver); 
		BoolVar[] varsOr_cmc1 = new BoolVar[2];
		varsOr_cmc1[0] = cl_gcp_compute_computeengine;
		varsOr_cmc1[1] = cl_aws_compute;
		solver.post(IntConstraintFactory.sum(varsOr_cmc1, sum_cmc1));
		Constraint or1_cmc1 = IntConstraintFactory.arithm(sum_cmc1, "=", 1);
		or1_cmc1.setName(Utilities.OR_TC);

		Constraint or0_cmc1= IntConstraintFactory.arithm(sum_cmc1, "=", 0);
		or0_cmc1.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_compute, or1_cmc1, or0_cmc1);
		
		IntVar sum_cmc2 = VariableFactory.enumerated("sum_cmc2", 0, 1, solver); 
		BoolVar[] varsOr_cmc2 = new BoolVar[2];
		varsOr_cmc2[0] = cl_gcp_storage_object;
		varsOr_cmc2[1] = cl_aws_storage_s3;
		solver.post(IntConstraintFactory.sum(varsOr_cmc2, sum_cmc2));
		Constraint or1_cmc2 = IntConstraintFactory.arithm(sum_cmc2, "=", 1);
		or1_cmc2.setName(Utilities.OR_TC);

		Constraint or0_cmc2 = IntConstraintFactory.arithm(sum_cmc2, "=", 0);
		or0_cmc2.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_storage_block, or1_cmc2, or0_cmc2);
		
		IntVar sum_cmc3 = VariableFactory.enumerated("sum_cmc3", 0, 1, solver); 
		BoolVar[] varsOr_cmc3 = new BoolVar[2];
		varsOr_cmc3[0] = cl_aws_messaging;
		varsOr_cmc3[1] = cl_gcp_bigdata_pubsub;
		solver.post(IntConstraintFactory.sum(varsOr_cmc3, sum_cmc3));
		Constraint or1_cmc3 = IntConstraintFactory.arithm(sum_cmc3, "=", 1);
		or1_cmc3.setName(Utilities.OR_TC);

		Constraint or0_cmc3 = IntConstraintFactory.arithm(sum_cmc3, "=", 0);
		or0_cmc3.setName(Utilities.OR_TC);
		LogicalConstraintFactory.ifThenElse(cl_messaging, or1_cmc3, or0_cmc3);


		//--------------------------------------------
		//Solve
		//--------------------------------------------
		long start = System.currentTimeMillis();
		System.out.println("Started at: " + start);

		List<IntVar> varsscalabiltyList = new ArrayList<IntVar>(featureAttrscalabilty.values());
		IntVar[] varsscalabilty = new IntVar[featureAttrscalabilty.values().size()];

		for(int i = 0; i < varsscalabiltyList.size(); i++) {
			varsscalabilty[i] = VariableFactory.minus(varsscalabiltyList.get(i));
		}

		List<IntVar> varsslaList = new ArrayList<IntVar>(featureAttrsla.values());
		IntVar[] varssla = new IntVar[featureAttrsla.values().size()];

		for(int i = 0; i < varsslaList.size(); i++) {
			varssla[i] = VariableFactory.minus(varsslaList.get(i));
		}

		IntVar totalscalabilty = VariableFactory.bounded("totalscalabilty", -1000000, 0, solver);
		solver.post(IntConstraintFactory.sum(varsscalabilty, totalscalabilty));
		IntVar totalsla = VariableFactory.bounded("totalsla", -1000000, 0, solver);
		solver.post(IntConstraintFactory.sum(varssla, totalsla));

		SMF.limitSolution(solver, 10);
		Chatterbox.showSolutions(solver);
		solver.findParetoFront(ResolutionPolicy.MINIMIZE, totalscalabilty, totalsla);
		//solver.findAllSolutions();
		Chatterbox.printStatistics(solver);


		long end = System.currentTimeMillis();
		System.out.println("Ended at: " + end);
		System.out.println("Total time: " + (end - start));
	}

	private static void initializeVars(){
		int contFeatures = 107;

		cl_cloud = (BoolVar) VariableFactory.fixed("feature_cl_cloud", 1, solver);
		cl_authentication = (BoolVar) VariableFactory.fixed("feature_cl_authentication", 1, solver);
		cl_auth_saml = VariableFactory.bool("feature_cl_auth_saml", solver);
		cl_auth_oauth = VariableFactory.bool("feature_cl_auth_oauth", solver);
		cl_auth_pki = VariableFactory.bool("feature_cl_auth_pki", solver);
		cl_auth_otp = VariableFactory.bool("feature_cl_auth_otp", solver);
		cl_auth_otp_sms = VariableFactory.bool("feature_cl_auth_otp_sms", solver);
		cl_auth_otp_email = VariableFactory.bool("feature_cl_auth_otp_email", solver);
		cl_auth_push = VariableFactory.bool("feature_cl_auth_push", solver);
		cl_auth_token = VariableFactory.bool("feature_cl_auth_token", solver);
		cl_auth_token_hard = VariableFactory.bool("feature_cl_auth_token_hard", solver);
		cl_auth_token_soft = VariableFactory.bool("feature_cl_auth_token_soft", solver);
		cld_auth_qrcode = VariableFactory.bool("feature_cld_auth_qrcode", solver);
		cl_compute = (BoolVar) VariableFactory.fixed("feature_cl_compute", 1, solver);
		cl_compute_osinstances = VariableFactory.bool("feature_cl_compute_osinstances", solver);
		cl_compute_osinstances_windows = VariableFactory.bool("feature_cl_compute_osinstances_windows", solver);
		cl_compute_osinstances_linux = VariableFactory.bool("feature_cl_compute_osinstances_linux", solver);
		cl_compute_osinstances_linux_ubuntu = VariableFactory.bool("feature_cl_compute_osinstances_linux_ubuntu", solver);
		cl_compute_osinstances_linux_debian = VariableFactory.bool("feature_cl_compute_osinstances_linux_debian", solver);
		cl_compute_osinstances_linux_redhat = VariableFactory.bool("feature_cl_compute_osinstances_linux_redhat", solver);
		cl_compute_osinstances_linux_fedora = VariableFactory.bool("feature_cl_compute_osinstances_linux_fedora", solver);
		cl_compute_osinstances_linux_suse = VariableFactory.bool("feature_cl_compute_osinstances_linux_suse", solver);
		cl_compute_appplatform = VariableFactory.bool("feature_cl_compute_appplatform", solver);
		cl_compute_containers = VariableFactory.bool("feature_cl_compute_containers", solver);
		cl_compute_autoscaling = VariableFactory.bool("feature_cl_compute_autoscaling", solver);
		cl_storage = VariableFactory.bool("feature_cl_storage", solver);
		cl_storage_block = VariableFactory.bool("feature_cl_storage_block", solver);
		cl_storage_block_hdd = VariableFactory.bool("feature_cl_storage_block_hdd", solver);
		cl_storage_block_ssd = VariableFactory.bool("feature_cl_storage_block_ssd", solver);
		cl_storage_object = (BoolVar) VariableFactory.fixed("feature_cl_storage_object", 1, solver);
		cl_storage_cache = VariableFactory.bool("feature_cl_storage_cache", solver);
		cl_storage_cache_engine = VariableFactory.bool("feature_cl_storage_cache_engine", solver);
		cl_storage_cache_memcache = VariableFactory.bool("feature_cl_storage_cache_memcache", solver);
		cl_storage_cache_memcached = VariableFactory.bool("feature_cl_storage_cache_memcached", solver);
		cl_storage_cache_redis = VariableFactory.bool("feature_cl_storage_cache_redis", solver);
		cl_storage_database = VariableFactory.bool("feature_cl_storage_database", solver);
		cl_storage_db_engine = VariableFactory.bool("feature_cl_storage_db_engine", solver);
		cl_storage_database_dbengine_sql = VariableFactory.bool("feature_cl_storage_database_dbengine_sql", solver);
		cl_storage_database_dbengine_sql_posgresql = VariableFactory.bool("feature_cl_storage_database_dbengine_sql_posgresql", solver);
		cl_storage_database_dbengine_sql_mysql = VariableFactory.bool("feature_cl_storage_database_dbengine_sql_mysql", solver);
		cl_storage_database_dbengine_sql_sqlserver = VariableFactory.bool("feature_cl_storage_database_dbengine_sql_sqlserver", solver);
		cl_storage_database_dbengine_sql_oracle = VariableFactory.bool("feature_cl_storage_database_dbengine_sql_oracle", solver);
		cl_storage_database_dbengine_nosql = VariableFactory.bool("feature_cl_storage_database_dbengine_nosql", solver);
		cl_signature = (BoolVar) VariableFactory.fixed("feature_cl_signature", 1, solver);
		cl_messaging = VariableFactory.bool("feature_cl_messaging", solver);
		cl_messaging_queues = VariableFactory.bool("feature_cl_messaging_queues", solver);
		cl_messaging_notification = VariableFactory.bool("feature_cl_messaging_notification", solver);
		cl_messaging_mailing = VariableFactory.bool("feature_cl_messaging_mailing", solver);
		cl_network = VariableFactory.bool("feature_cl_network", solver);
		cl_networking_cdn = VariableFactory.bool("feature_cl_networking_cdn", solver);
		cl_networking_dns = VariableFactory.bool("feature_cl_networking_dns", solver);
		cl_networking_loadbalancing = VariableFactory.bool("feature_cl_networking_loadbalancing", solver);
		cl_monitoring = VariableFactory.bool("feature_cl_monitoring", solver);
		cl_audit = VariableFactory.bool("feature_cl_audit", solver);
		cl_aws = (BoolVar) VariableFactory.fixed("feature_cl_aws", 1, solver);
		cl_aws_compute = (BoolVar) VariableFactory.fixed("feature_cl_aws_compute", 0, solver);
		cl_aws_compute_ec2 = VariableFactory.bool("feature_cl_aws_compute_ec2", solver);
		cl_aws_compute_ec2_windows = VariableFactory.bool("feature_cl_aws_compute_ec2_windows", solver);
		cl_compute_ec2_linux = VariableFactory.bool("feature_cl_compute_ec2_linux", solver);
		cl_aws_compute_lambda = VariableFactory.bool("feature_cl_aws_compute_lambda", solver);
		cl_aws_compute_container_service = VariableFactory.bool("feature_cl_aws_compute_container_service", solver);
		cl_aws_storage = VariableFactory.bool("feature_cl_aws_storage", solver);
		cl_aws_storage_s3 = VariableFactory.bool("feature_cl_aws_storage_s3", solver);
		cl_aws_storage_ebs = VariableFactory.bool("feature_cl_aws_storage_ebs", solver);
		cl_aws_storage_ebs_ssd = VariableFactory.bool("feature_cl_aws_storage_ebs_ssd", solver);
		cl_aws_storage_ebs_magnetic = VariableFactory.bool("feature_cl_aws_storage_ebs_magnetic", solver);
		cl_aws_storage_glacier = VariableFactory.bool("feature_cl_aws_storage_glacier", solver);
		cl_aws_database = VariableFactory.bool("feature_cl_aws_database", solver);
		cl_aws_database_aurora = VariableFactory.bool("feature_cl_aws_database_aurora", solver);
		cl_aws_storage_rds = VariableFactory.bool("feature_cl_aws_storage_rds", solver);
		cl_aws_database_posgresql = VariableFactory.bool("feature_cl_aws_database_posgresql", solver);
		cl_aws_database_rds_mysql = VariableFactory.bool("feature_cl_aws_database_rds_mysql", solver);
		cl_aws_database_rds_sqlserver = VariableFactory.bool("feature_cl_aws_database_rds_sqlserver", solver);
		cl_aws_database_rds_oracle = VariableFactory.bool("feature_cl_aws_database_rds_oracle", solver);
		cl_aws_messaging = VariableFactory.bool("feature_cl_aws_messaging", solver);
		cl_aws_messaging_ses = VariableFactory.bool("feature_cl_aws_messaging_ses", solver);
		cl_aws_messaging_sns = VariableFactory.bool("feature_cl_aws_messaging_sns", solver);
		cl_aws_networking = VariableFactory.bool("feature_cl_aws_networking", solver);
		cl_aws_networking_cloudfront = VariableFactory.bool("feature_cl_aws_networking_cloudfront", solver);
		cl_aws_networking_route53 = VariableFactory.bool("feature_cl_aws_networking_route53", solver);
		cl_aws_networking_elb = VariableFactory.bool("feature_cl_aws_networking_elb", solver);
		cl_aws_authentication = VariableFactory.bool("feature_cl_aws_authentication", solver);
		cl_gcp = (BoolVar) VariableFactory.fixed("feature_cl_gcp", 1, solver);
		cl_gcp_compute = VariableFactory.bool("feature_cl_gcp_compute", solver);
		cl_gcp_compute_computeengine = VariableFactory.bool("feature_cl_gcp_compute_computeengine", solver);
		cl_gcp_compute_appengine = VariableFactory.bool("feature_cl_gcp_compute_appengine", solver);
		cl_gcp_compute_containerengine = VariableFactory.bool("feature_cl_gcp_compute_containerengine", solver);
		cl_gcp_storage = VariableFactory.bool("feature_cl_gcp_storage", solver);
		cl_gcp_storage_object = VariableFactory.bool("feature_cl_gcp_storage_object", solver);
		cl_gcp_database = VariableFactory.bool("feature_cl_gcp_database", solver);
		cl_gcp_database_nosql = VariableFactory.bool("feature_cl_gcp_database_nosql", solver);
		cl_gcp_database_nosql_datastore = VariableFactory.bool("feature_cl_gcp_database_nosql_datastore", solver);
		cl_gcp_database_bigtable = VariableFactory.bool("feature_cl_gcp_database_bigtable", solver);
		cl_gcp_storage_database_cloudsql = VariableFactory.bool("feature_cl_gcp_storage_database_cloudsql", solver);
		cl_gcp_storage_cloudstorage = VariableFactory.bool("feature_cl_gcp_storage_cloudstorage", solver);
		cl_gcp_storage_standard = VariableFactory.bool("feature_cl_gcp_storage_standard", solver);
		cl_gcp_storage_nearline = VariableFactory.bool("feature_cl_gcp_storage_nearline", solver);
		cl_gcp_storage_coldline = VariableFactory.bool("feature_cl_gcp_storage_coldline", solver);
		cl_gcp_storage_bigtable = VariableFactory.bool("feature_cl_gcp_storage_bigtable", solver);
		cl_gcp_networking = VariableFactory.bool("feature_cl_gcp_networking", solver);
		cl_gcp_cdn = VariableFactory.bool("feature_cl_gcp_cdn", solver);
		cl_gcp_dns = VariableFactory.bool("feature_cl_gcp_dns", solver);
		cl_gcp_loadbalancing = VariableFactory.bool("feature_cl_gcp_loadbalancing", solver);
		cl_gcp_authentication = VariableFactory.bool("feature_cl_gcp_authentication", solver);
		cl_gcp_authentication_iam = VariableFactory.bool("feature_cl_gcp_authentication_iam", solver);
		cl_gcp_bigdata = VariableFactory.bool("feature_cl_gcp_bigdata", solver);
		cl_gcp_bigdata_pubsub = VariableFactory.bool("feature_cl_gcp_bigdata_pubsub", solver);
	}

	private static void initializeFeatureAttributes(){
		featureAttrsla = new HashMap<String, IntVar>();
		featureAttrauditability = new HashMap<String, IntVar>();
		featureAttrcompliance = new HashMap<String, IntVar>();
		featureAttrease_of_doing_business = new HashMap<String, IntVar>();
		featureAttrownership = new HashMap<String, IntVar>();
		featureAttrprovider_business_stability = new HashMap<String, IntVar>();
		featureAttrprovider_support = new HashMap<String, IntVar>();
		featureAttrelasticity = new HashMap<String, IntVar>();
		featureAttrportability = new HashMap<String, IntVar>();
		featureAttrscalabilty = new HashMap<String, IntVar>();
		featureAttrinteroperability = new HashMap<String, IntVar>();
		featureAttrlearnalability = new HashMap<String, IntVar>();

		featureAttrauditability.put("cl_aws", VariableFactory.enumerated("cl_awsauditability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrauditability.get("cl_aws"), ">=", 1), IntConstraintFactory.arithm(featureAttrauditability.get("cl_aws"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws, "=", 0), IntConstraintFactory.arithm(featureAttrauditability.get("cl_aws"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws, "=", 1), IntConstraintFactory.arithm(featureAttrauditability.get("cl_aws"), "!=", 0));
		featureAttrcompliance.put("cl_aws", VariableFactory.enumerated("cl_awscompliance", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrcompliance.get("cl_aws"), ">=", 3), IntConstraintFactory.arithm(featureAttrcompliance.get("cl_aws"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws, "=", 0), IntConstraintFactory.arithm(featureAttrcompliance.get("cl_aws"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws, "=", 1), IntConstraintFactory.arithm(featureAttrcompliance.get("cl_aws"), "!=", 0));
		featureAttrease_of_doing_business.put("cl_aws", VariableFactory.enumerated("cl_awsease_of_doing_business", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrease_of_doing_business.get("cl_aws"), ">=", 2), IntConstraintFactory.arithm(featureAttrease_of_doing_business.get("cl_aws"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws, "=", 0), IntConstraintFactory.arithm(featureAttrease_of_doing_business.get("cl_aws"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws, "=", 1), IntConstraintFactory.arithm(featureAttrease_of_doing_business.get("cl_aws"), "!=", 0));
		featureAttrprovider_business_stability.put("cl_aws", VariableFactory.enumerated("cl_awsprovider_business_stability", new int[]{0, 100}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrprovider_business_stability.get("cl_aws"), ">=", 100), IntConstraintFactory.arithm(featureAttrprovider_business_stability.get("cl_aws"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws, "=", 0), IntConstraintFactory.arithm(featureAttrprovider_business_stability.get("cl_aws"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws, "=", 1), IntConstraintFactory.arithm(featureAttrprovider_business_stability.get("cl_aws"), "!=", 0));
		featureAttrprovider_support.put("cl_aws", VariableFactory.enumerated("cl_awsprovider_support", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrprovider_support.get("cl_aws"), ">=", 2), IntConstraintFactory.arithm(featureAttrprovider_support.get("cl_aws"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws, "=", 0), IntConstraintFactory.arithm(featureAttrprovider_support.get("cl_aws"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws, "=", 1), IntConstraintFactory.arithm(featureAttrprovider_support.get("cl_aws"), "!=", 0));
		featureAttrsla.put("cl_aws_compute_ec2", VariableFactory.enumerated("cl_aws_compute_ec2sla", new int[]{0, 9400}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrsla.get("cl_aws_compute_ec2"), ">=", 9400), IntConstraintFactory.arithm(featureAttrsla.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 0), IntConstraintFactory.arithm(featureAttrsla.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 1), IntConstraintFactory.arithm(featureAttrsla.get("cl_aws_compute_ec2"), "!=", 0));
		featureAttrelasticity.put("cl_aws_compute_ec2", VariableFactory.enumerated("cl_aws_compute_ec2elasticity", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_ec2"), ">=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_ec2"), "!=", 0));
		featureAttrscalabilty.put("cl_aws_compute_ec2", VariableFactory.enumerated("cl_aws_compute_ec2scalabilty", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_ec2"), ">=", 2), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_ec2"), "!=", 0));
		featureAttrportability.put("cl_aws_compute_ec2", VariableFactory.enumerated("cl_aws_compute_ec2portability", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_ec2"), ">=", 2), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_ec2"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_compute_ec2", VariableFactory.enumerated("cl_aws_compute_ec2interoperability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_compute_ec2"), ">=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_compute_ec2"), "!=", 0));
		featureAttrlearnalability.put("cl_aws_compute_ec2", VariableFactory.enumerated("cl_aws_compute_ec2learnalability", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_compute_ec2"), ">=", 2), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 0), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_compute_ec2"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_ec2, "=", 1), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_compute_ec2"), "!=", 0));
		featureAttrelasticity.put("cl_aws_compute_lambda", VariableFactory.enumerated("cl_aws_compute_lambdaelasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_lambda"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_lambda"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_lambda, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_lambda"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_lambda, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_lambda"), "!=", 0));
		featureAttrportability.put("cl_aws_compute_lambda", VariableFactory.enumerated("cl_aws_compute_lambdaportability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_lambda"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_lambda"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_lambda, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_lambda"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_lambda, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_lambda"), "!=", 0));
		featureAttrscalabilty.put("cl_aws_compute_lambda", VariableFactory.enumerated("cl_aws_compute_lambdascalabilty", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_lambda"), ">=", 3), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_lambda"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_lambda, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_lambda"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_lambda, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_lambda"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_compute_lambda", VariableFactory.enumerated("cl_aws_compute_lambdainteroperability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_compute_lambda"), ">=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_compute_lambda"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_lambda, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_compute_lambda"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_lambda, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_compute_lambda"), "!=", 0));
		featureAttrelasticity.put("cl_aws_compute_container_service", VariableFactory.enumerated("cl_aws_compute_container_serviceelasticity", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_container_service"), ">=", 2), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_container_service"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_container_service, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_container_service"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_container_service, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_compute_container_service"), "!=", 0));
		featureAttrportability.put("cl_aws_compute_container_service", VariableFactory.enumerated("cl_aws_compute_container_serviceportability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_container_service"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_container_service"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_container_service, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_container_service"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_container_service, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_compute_container_service"), "!=", 0));
		featureAttrscalabilty.put("cl_aws_compute_container_service", VariableFactory.enumerated("cl_aws_compute_container_servicescalabilty", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_container_service"), ">=", 3), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_container_service"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_container_service, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_container_service"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_container_service, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_compute_container_service"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_compute_container_service", VariableFactory.enumerated("cl_aws_compute_container_serviceinteroperability", new int[]{0, 0}, solver));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_container_service, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_compute_container_service"), "=", 0));
		featureAttrlearnalability.put("cl_aws_compute_container_service", VariableFactory.enumerated("cl_aws_compute_container_servicelearnalability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_compute_container_service"), ">=", 1), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_compute_container_service"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_container_service, "=", 0), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_compute_container_service"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_compute_container_service, "=", 1), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_compute_container_service"), "!=", 0));
		featureAttrsla.put("cl_aws_storage_s3", VariableFactory.enumerated("cl_aws_storage_s3sla", new int[]{0, 9999}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrsla.get("cl_aws_storage_s3"), ">=", 9999), IntConstraintFactory.arithm(featureAttrsla.get("cl_aws_storage_s3"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_s3, "=", 0), IntConstraintFactory.arithm(featureAttrsla.get("cl_aws_storage_s3"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_s3, "=", 1), IntConstraintFactory.arithm(featureAttrsla.get("cl_aws_storage_s3"), "!=", 0));
		featureAttrelasticity.put("cl_aws_storage_s3", VariableFactory.enumerated("cl_aws_storage_s3elasticity", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_s3"), ">=", 2), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_s3"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_s3, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_s3"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_s3, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_s3"), "!=", 0));
		featureAttrportability.put("cl_aws_storage_s3", VariableFactory.enumerated("cl_aws_storage_s3portability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_s3"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_s3"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_s3, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_s3"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_s3, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_s3"), "!=", 0));
		featureAttrscalabilty.put("cl_aws_storage_s3", VariableFactory.enumerated("cl_aws_storage_s3scalabilty", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_s3"), ">=", 3), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_s3"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_s3, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_s3"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_s3, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_s3"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_storage_s3", VariableFactory.enumerated("cl_aws_storage_s3interoperability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_s3"), ">=", 3), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_s3"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_s3, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_s3"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_s3, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_s3"), "!=", 0));
		featureAttrelasticity.put("cl_aws_storage_ebs", VariableFactory.enumerated("cl_aws_storage_ebselasticity", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_ebs"), ">=", 2), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_ebs"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_ebs, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_ebs"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_ebs, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_ebs"), "!=", 0));
		featureAttrportability.put("cl_aws_storage_ebs", VariableFactory.enumerated("cl_aws_storage_ebsportability", new int[]{0, 0}, solver));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_ebs, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_ebs"), "=", 0));
		featureAttrscalabilty.put("cl_aws_storage_ebs", VariableFactory.enumerated("cl_aws_storage_ebsscalabilty", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_ebs"), ">=", 2), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_ebs"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_ebs, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_ebs"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_ebs, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_ebs"), "!=", 0));
		featureAttrlearnalability.put("cl_aws_storage_ebs", VariableFactory.enumerated("cl_aws_storage_ebslearnalability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_storage_ebs"), ">=", 1), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_storage_ebs"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_ebs, "=", 0), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_storage_ebs"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_ebs, "=", 1), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_storage_ebs"), "!=", 0));
		featureAttrelasticity.put("cl_aws_storage_glacier", VariableFactory.enumerated("cl_aws_storage_glacierelasticity", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_glacier"), ">=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_glacier"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_glacier, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_glacier"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_glacier, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_glacier"), "!=", 0));
		featureAttrportability.put("cl_aws_storage_glacier", VariableFactory.enumerated("cl_aws_storage_glacierportability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_glacier"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_glacier"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_glacier, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_glacier"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_glacier, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_glacier"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_storage_glacier", VariableFactory.enumerated("cl_aws_storage_glacierinteroperability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_glacier"), ">=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_glacier"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_glacier, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_glacier"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_glacier, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_glacier"), "!=", 0));
		featureAttrlearnalability.put("cl_aws_storage_glacier", VariableFactory.enumerated("cl_aws_storage_glacierlearnalability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_storage_glacier"), ">=", 3), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_storage_glacier"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_glacier, "=", 0), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_storage_glacier"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_glacier, "=", 1), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_aws_storage_glacier"), "!=", 0));
		featureAttrelasticity.put("cl_aws_database_aurora", VariableFactory.enumerated("cl_aws_database_auroraelasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_database_aurora"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_database_aurora"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_database_aurora, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_database_aurora"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_database_aurora, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_database_aurora"), "!=", 0));
		featureAttrportability.put("cl_aws_database_aurora", VariableFactory.enumerated("cl_aws_database_auroraportability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_database_aurora"), ">=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_database_aurora"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_database_aurora, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_database_aurora"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_database_aurora, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_database_aurora"), "!=", 0));
		featureAttrscalabilty.put("cl_aws_database_aurora", VariableFactory.enumerated("cl_aws_database_aurorascalabilty", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_database_aurora"), ">=", 3), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_database_aurora"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_database_aurora, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_database_aurora"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_database_aurora, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_database_aurora"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_database_aurora", VariableFactory.enumerated("cl_aws_database_aurorainteroperability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_database_aurora"), ">=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_database_aurora"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_database_aurora, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_database_aurora"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_database_aurora, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_database_aurora"), "!=", 0));
		featureAttrelasticity.put("cl_aws_storage_rds", VariableFactory.enumerated("cl_aws_storage_rdselasticity", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_rds"), ">=", 2), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_rds"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_rds, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_rds"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_rds, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_storage_rds"), "!=", 0));
		featureAttrportability.put("cl_aws_storage_rds", VariableFactory.enumerated("cl_aws_storage_rdsportability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_rds"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_rds"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_rds, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_rds"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_rds, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_storage_rds"), "!=", 0));
		featureAttrscalabilty.put("cl_aws_storage_rds", VariableFactory.enumerated("cl_aws_storage_rdsscalabilty", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_rds"), ">=", 2), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_rds"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_rds, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_rds"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_rds, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_storage_rds"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_storage_rds", VariableFactory.enumerated("cl_aws_storage_rdsinteroperability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_rds"), ">=", 3), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_rds"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_rds, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_rds"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_storage_rds, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_storage_rds"), "!=", 0));
		featureAttrelasticity.put("cl_aws_messaging_sns", VariableFactory.enumerated("cl_aws_messaging_snselasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_messaging_sns"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_messaging_sns"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_messaging_sns, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_messaging_sns"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_messaging_sns, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_messaging_sns"), "!=", 0));
		featureAttrportability.put("cl_aws_messaging_sns", VariableFactory.enumerated("cl_aws_messaging_snsportability", new int[]{0, 0}, solver));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_messaging_sns, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_messaging_sns"), "=", 0));
		featureAttrscalabilty.put("cl_aws_messaging_sns", VariableFactory.enumerated("cl_aws_messaging_snsscalabilty", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_messaging_sns"), ">=", 3), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_messaging_sns"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_messaging_sns, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_messaging_sns"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_messaging_sns, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_messaging_sns"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_messaging_sns", VariableFactory.enumerated("cl_aws_messaging_snsinteroperability", new int[]{0, 0}, solver));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_messaging_sns, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_messaging_sns"), "=", 0));
		featureAttrelasticity.put("cl_aws_networking_cloudfront", VariableFactory.enumerated("cl_aws_networking_cloudfrontelasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_cloudfront"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_cloudfront"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_cloudfront, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_cloudfront"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_cloudfront, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_cloudfront"), "!=", 0));
		featureAttrscalabilty.put("cl_aws_networking_cloudfront", VariableFactory.enumerated("cl_aws_networking_cloudfrontscalabilty", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_cloudfront"), ">=", 3), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_cloudfront"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_cloudfront, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_cloudfront"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_cloudfront, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_cloudfront"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_networking_cloudfront", VariableFactory.enumerated("cl_aws_networking_cloudfrontinteroperability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_networking_cloudfront"), ">=", 3), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_networking_cloudfront"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_cloudfront, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_networking_cloudfront"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_cloudfront, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_networking_cloudfront"), "!=", 0));
		featureAttrportability.put("cl_aws_networking_cloudfront", VariableFactory.enumerated("cl_aws_networking_cloudfrontportability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_cloudfront"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_cloudfront"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_cloudfront, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_cloudfront"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_cloudfront, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_cloudfront"), "!=", 0));
		featureAttrelasticity.put("cl_aws_networking_route53", VariableFactory.enumerated("cl_aws_networking_route53elasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_route53"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_route53"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_route53, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_route53"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_route53, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_route53"), "!=", 0));
		featureAttrportability.put("cl_aws_networking_route53", VariableFactory.enumerated("cl_aws_networking_route53portability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_route53"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_route53"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_route53, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_route53"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_route53, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_route53"), "!=", 0));
		featureAttrscalabilty.put("cl_aws_networking_route53", VariableFactory.enumerated("cl_aws_networking_route53scalabilty", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_route53"), ">=", 2), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_route53"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_route53, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_route53"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_route53, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_route53"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_networking_route53", VariableFactory.enumerated("cl_aws_networking_route53interoperability", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_networking_route53"), ">=", 2), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_networking_route53"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_route53, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_networking_route53"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_route53, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_networking_route53"), "!=", 0));
		featureAttrelasticity.put("cl_aws_networking_elb", VariableFactory.enumerated("cl_aws_networking_elbelasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_elb"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_elb"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_elb, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_elb"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_elb, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_aws_networking_elb"), "!=", 0));
		featureAttrportability.put("cl_aws_networking_elb", VariableFactory.enumerated("cl_aws_networking_elbportability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_elb"), ">=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_elb"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_elb, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_elb"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_elb, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_aws_networking_elb"), "!=", 0));
		featureAttrscalabilty.put("cl_aws_networking_elb", VariableFactory.enumerated("cl_aws_networking_elbscalabilty", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_elb"), ">=", 2), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_elb"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_elb, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_elb"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_elb, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_aws_networking_elb"), "!=", 0));
		featureAttrinteroperability.put("cl_aws_networking_elb", VariableFactory.enumerated("cl_aws_networking_elbinteroperability", new int[]{0, 0}, solver));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_aws_networking_elb, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_aws_networking_elb"), "=", 0));
		featureAttrauditability.put("cl_gcp", VariableFactory.enumerated("cl_gcpauditability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrauditability.get("cl_gcp"), ">=", 1), IntConstraintFactory.arithm(featureAttrauditability.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 0), IntConstraintFactory.arithm(featureAttrauditability.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 1), IntConstraintFactory.arithm(featureAttrauditability.get("cl_gcp"), "!=", 0));
		featureAttrcompliance.put("cl_gcp", VariableFactory.enumerated("cl_gcpcompliance", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrcompliance.get("cl_gcp"), ">=", 3), IntConstraintFactory.arithm(featureAttrcompliance.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 0), IntConstraintFactory.arithm(featureAttrcompliance.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 1), IntConstraintFactory.arithm(featureAttrcompliance.get("cl_gcp"), "!=", 0));
		featureAttrease_of_doing_business.put("cl_gcp", VariableFactory.enumerated("cl_gcpease_of_doing_business", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrease_of_doing_business.get("cl_gcp"), ">=", 3), IntConstraintFactory.arithm(featureAttrease_of_doing_business.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 0), IntConstraintFactory.arithm(featureAttrease_of_doing_business.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 1), IntConstraintFactory.arithm(featureAttrease_of_doing_business.get("cl_gcp"), "!=", 0));
		featureAttrownership.put("cl_gcp", VariableFactory.enumerated("cl_gcpownership", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrownership.get("cl_gcp"), ">=", 1), IntConstraintFactory.arithm(featureAttrownership.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 0), IntConstraintFactory.arithm(featureAttrownership.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 1), IntConstraintFactory.arithm(featureAttrownership.get("cl_gcp"), "!=", 0));
		featureAttrprovider_business_stability.put("cl_gcp", VariableFactory.enumerated("cl_gcpprovider_business_stability", new int[]{0, 100}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrprovider_business_stability.get("cl_gcp"), ">=", 100), IntConstraintFactory.arithm(featureAttrprovider_business_stability.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 0), IntConstraintFactory.arithm(featureAttrprovider_business_stability.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 1), IntConstraintFactory.arithm(featureAttrprovider_business_stability.get("cl_gcp"), "!=", 0));
		featureAttrprovider_support.put("cl_gcp", VariableFactory.enumerated("cl_gcpprovider_support", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrprovider_support.get("cl_gcp"), ">=", 3), IntConstraintFactory.arithm(featureAttrprovider_support.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 0), IntConstraintFactory.arithm(featureAttrprovider_support.get("cl_gcp"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp, "=", 1), IntConstraintFactory.arithm(featureAttrprovider_support.get("cl_gcp"), "!=", 0));
		featureAttrelasticity.put("cl_gcp_compute_computeengine", VariableFactory.enumerated("cl_gcp_compute_computeengineelasticity", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_computeengine"), ">=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_computeengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_computeengine, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_computeengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_computeengine, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_computeengine"), "!=", 0));
		featureAttrportability.put("cl_gcp_compute_computeengine", VariableFactory.enumerated("cl_gcp_compute_computeengineportability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_computeengine"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_computeengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_computeengine, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_computeengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_computeengine, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_computeengine"), "!=", 0));
		featureAttrscalabilty.put("cl_gcp_compute_computeengine", VariableFactory.enumerated("cl_gcp_compute_computeenginescalabilty", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_computeengine"), ">=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_computeengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_computeengine, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_computeengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_computeengine, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_computeengine"), "!=", 0));
		featureAttrinteroperability.put("cl_gcp_compute_computeengine", VariableFactory.enumerated("cl_gcp_compute_computeengineinteroperability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_computeengine"), ">=", 3), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_computeengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_computeengine, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_computeengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_computeengine, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_computeengine"), "!=", 0));
		featureAttrlearnalability.put("cl_gcp_compute_computeengine", VariableFactory.enumerated("cl_gcp_compute_computeenginelearnalability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_gcp_compute_computeengine"), ">=", 1), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_gcp_compute_computeengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_computeengine, "=", 0), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_gcp_compute_computeengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_computeengine, "=", 1), IntConstraintFactory.arithm(featureAttrlearnalability.get("cl_gcp_compute_computeengine"), "!=", 0));
		featureAttrelasticity.put("cl_gcp_compute_appengine", VariableFactory.enumerated("cl_gcp_compute_appengineelasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_appengine"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_appengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_appengine, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_appengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_appengine, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_appengine"), "!=", 0));
		featureAttrportability.put("cl_gcp_compute_appengine", VariableFactory.enumerated("cl_gcp_compute_appengineportability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_appengine"), ">=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_appengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_appengine, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_appengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_appengine, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_appengine"), "!=", 0));
		featureAttrscalabilty.put("cl_gcp_compute_appengine", VariableFactory.enumerated("cl_gcp_compute_appenginescalabilty", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_appengine"), ">=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_appengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_appengine, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_appengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_appengine, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_appengine"), "!=", 0));
		featureAttrinteroperability.put("cl_gcp_compute_appengine", VariableFactory.enumerated("cl_gcp_compute_appengineinteroperability", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_appengine"), ">=", 2), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_appengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_appengine, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_appengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_appengine, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_appengine"), "!=", 0));
		featureAttrelasticity.put("cl_gcp_compute_containerengine", VariableFactory.enumerated("cl_gcp_compute_containerengineelasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_containerengine"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_containerengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_containerengine, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_containerengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_containerengine, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_compute_containerengine"), "!=", 0));
		featureAttrportability.put("cl_gcp_compute_containerengine", VariableFactory.enumerated("cl_gcp_compute_containerengineportability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_containerengine"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_containerengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_containerengine, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_containerengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_containerengine, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_compute_containerengine"), "!=", 0));
		featureAttrscalabilty.put("cl_gcp_compute_containerengine", VariableFactory.enumerated("cl_gcp_compute_containerenginescalabilty", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_containerengine"), ">=", 3), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_containerengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_containerengine, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_containerengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_containerengine, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_compute_containerengine"), "!=", 0));
		featureAttrinteroperability.put("cl_gcp_compute_containerengine", VariableFactory.enumerated("cl_gcp_compute_containerengineinteroperability", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_containerengine"), ">=", 2), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_containerengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_containerengine, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_containerengine"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_compute_containerengine, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_compute_containerengine"), "!=", 0));
		featureAttrelasticity.put("cl_gcp_storage_object", VariableFactory.enumerated("cl_gcp_storage_objectelasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_object"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_object"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_object, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_object"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_object, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_object"), "!=", 0));
		featureAttrportability.put("cl_gcp_storage_object", VariableFactory.enumerated("cl_gcp_storage_objectportability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_object"), ">=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_object"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_object, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_object"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_object, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_object"), "!=", 0));
		featureAttrscalabilty.put("cl_gcp_storage_object", VariableFactory.enumerated("cl_gcp_storage_objectscalabilty", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_object"), ">=", 2), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_object"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_object, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_object"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_object, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_object"), "!=", 0));
		featureAttrinteroperability.put("cl_gcp_storage_object", VariableFactory.enumerated("cl_gcp_storage_objectinteroperability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_storage_object"), ">=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_storage_object"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_object, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_storage_object"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_object, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_storage_object"), "!=", 0));
		featureAttrelasticity.put("cl_gcp_database_nosql_datastore", VariableFactory.enumerated("cl_gcp_database_nosql_datastoreelasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_database_nosql_datastore"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_database_nosql_datastore"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_nosql_datastore, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_database_nosql_datastore"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_nosql_datastore, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_database_nosql_datastore"), "!=", 0));
		featureAttrportability.put("cl_gcp_database_nosql_datastore", VariableFactory.enumerated("cl_gcp_database_nosql_datastoreportability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_database_nosql_datastore"), ">=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_database_nosql_datastore"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_nosql_datastore, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_database_nosql_datastore"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_nosql_datastore, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_database_nosql_datastore"), "!=", 0));
		featureAttrscalabilty.put("cl_gcp_database_nosql_datastore", VariableFactory.enumerated("cl_gcp_database_nosql_datastorescalabilty", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_database_nosql_datastore"), ">=", 2), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_database_nosql_datastore"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_nosql_datastore, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_database_nosql_datastore"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_nosql_datastore, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_database_nosql_datastore"), "!=", 0));
		featureAttrinteroperability.put("cl_gcp_database_nosql_datastore", VariableFactory.enumerated("cl_gcp_database_nosql_datastoreinteroperability", new int[]{0, 0}, solver));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_nosql_datastore, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_database_nosql_datastore"), "=", 0));
		featureAttrportability.put("cl_gcp_database_bigtable", VariableFactory.enumerated("cl_gcp_database_bigtableportability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_database_bigtable"), ">=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_database_bigtable"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_bigtable, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_database_bigtable"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_bigtable, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_database_bigtable"), "!=", 0));
		featureAttrinteroperability.put("cl_gcp_database_bigtable", VariableFactory.enumerated("cl_gcp_database_bigtableinteroperability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_database_bigtable"), ">=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_database_bigtable"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_bigtable, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_database_bigtable"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_bigtable, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_database_bigtable"), "!=", 0));
		featureAttrscalabilty.put("cl_gcp_database_bigtable", VariableFactory.enumerated("cl_gcp_database_bigtablescalabilty", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_database_bigtable"), ">=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_database_bigtable"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_bigtable, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_database_bigtable"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_database_bigtable, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_database_bigtable"), "!=", 0));
		featureAttrelasticity.put("cl_gcp_storage_database_cloudsql", VariableFactory.enumerated("cl_gcp_storage_database_cloudsqlelasticity", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_database_cloudsql"), ">=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_database_cloudsql"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_database_cloudsql, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_database_cloudsql"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_database_cloudsql, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_database_cloudsql"), "!=", 0));
		featureAttrportability.put("cl_gcp_storage_database_cloudsql", VariableFactory.enumerated("cl_gcp_storage_database_cloudsqlportability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_database_cloudsql"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_database_cloudsql"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_database_cloudsql, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_database_cloudsql"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_database_cloudsql, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_database_cloudsql"), "!=", 0));
		featureAttrscalabilty.put("cl_gcp_storage_database_cloudsql", VariableFactory.enumerated("cl_gcp_storage_database_cloudsqlscalabilty", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_database_cloudsql"), ">=", 2), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_database_cloudsql"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_database_cloudsql, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_database_cloudsql"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_database_cloudsql, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_database_cloudsql"), "!=", 0));
		featureAttrinteroperability.put("cl_gcp_storage_database_cloudsql", VariableFactory.enumerated("cl_gcp_storage_database_cloudsqlinteroperability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_storage_database_cloudsql"), ">=", 3), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_storage_database_cloudsql"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_database_cloudsql, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_storage_database_cloudsql"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_database_cloudsql, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_storage_database_cloudsql"), "!=", 0));
		featureAttrelasticity.put("cl_gcp_storage_cloudstorage", VariableFactory.enumerated("cl_gcp_storage_cloudstorageelasticity", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_cloudstorage"), ">=", 2), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_cloudstorage"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_cloudstorage, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_cloudstorage"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_cloudstorage, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_storage_cloudstorage"), "!=", 0));
		featureAttrportability.put("cl_gcp_storage_cloudstorage", VariableFactory.enumerated("cl_gcp_storage_cloudstorageportability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_cloudstorage"), ">=", 3), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_cloudstorage"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_cloudstorage, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_cloudstorage"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_cloudstorage, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_storage_cloudstorage"), "!=", 0));
		featureAttrscalabilty.put("cl_gcp_storage_cloudstorage", VariableFactory.enumerated("cl_gcp_storage_cloudstoragescalabilty", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_cloudstorage"), ">=", 3), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_cloudstorage"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_cloudstorage, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_cloudstorage"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_storage_cloudstorage, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_storage_cloudstorage"), "!=", 0));
		featureAttrelasticity.put("cl_gcp_cdn", VariableFactory.enumerated("cl_gcp_cdnelasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_cdn"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_cdn"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_cdn, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_cdn"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_cdn, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_cdn"), "!=", 0));
		featureAttrportability.put("cl_gcp_cdn", VariableFactory.enumerated("cl_gcp_cdnportability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_cdn"), ">=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_cdn"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_cdn, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_cdn"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_cdn, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_cdn"), "!=", 0));
		featureAttrscalabilty.put("cl_gcp_cdn", VariableFactory.enumerated("cl_gcp_cdnscalabilty", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_cdn"), ">=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_cdn"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_cdn, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_cdn"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_cdn, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_cdn"), "!=", 0));
		featureAttrinteroperability.put("cl_gcp_cdn", VariableFactory.enumerated("cl_gcp_cdninteroperability", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_cdn"), ">=", 3), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_cdn"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_cdn, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_cdn"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_cdn, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_cdn"), "!=", 0));
		featureAttrelasticity.put("cl_gcp_dns", VariableFactory.enumerated("cl_gcp_dnselasticity", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_dns"), ">=", 3), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_dns"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_dns, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_dns"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_dns, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_dns"), "!=", 0));
		featureAttrportability.put("cl_gcp_dns", VariableFactory.enumerated("cl_gcp_dnsportability", new int[]{0, 0}, solver));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_dns, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_dns"), "=", 0));
		featureAttrscalabilty.put("cl_gcp_dns", VariableFactory.enumerated("cl_gcp_dnsscalabilty", new int[]{0, 3}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_dns"), ">=", 3), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_dns"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_dns, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_dns"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_dns, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_dns"), "!=", 0));
		featureAttrinteroperability.put("cl_gcp_dns", VariableFactory.enumerated("cl_gcp_dnsinteroperability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_dns"), ">=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_dns"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_dns, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_dns"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_dns, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_dns"), "!=", 0));
		featureAttrelasticity.put("cl_gcp_loadbalancing", VariableFactory.enumerated("cl_gcp_loadbalancingelasticity", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_loadbalancing"), ">=", 2), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_loadbalancing"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_loadbalancing, "=", 0), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_loadbalancing"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_loadbalancing, "=", 1), IntConstraintFactory.arithm(featureAttrelasticity.get("cl_gcp_loadbalancing"), "!=", 0));
		featureAttrportability.put("cl_gcp_loadbalancing", VariableFactory.enumerated("cl_gcp_loadbalancingportability", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_loadbalancing"), ">=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_loadbalancing"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_loadbalancing, "=", 0), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_loadbalancing"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_loadbalancing, "=", 1), IntConstraintFactory.arithm(featureAttrportability.get("cl_gcp_loadbalancing"), "!=", 0));
		featureAttrscalabilty.put("cl_gcp_loadbalancing", VariableFactory.enumerated("cl_gcp_loadbalancingscalabilty", new int[]{0, 1}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_loadbalancing"), ">=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_loadbalancing"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_loadbalancing, "=", 0), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_loadbalancing"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_loadbalancing, "=", 1), IntConstraintFactory.arithm(featureAttrscalabilty.get("cl_gcp_loadbalancing"), "!=", 0));
		featureAttrinteroperability.put("cl_gcp_loadbalancing", VariableFactory.enumerated("cl_gcp_loadbalancinginteroperability", new int[]{0, 2}, solver));
		LogicalConstraintFactory.or(IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_loadbalancing"), ">=", 2), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_loadbalancing"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_loadbalancing, "=", 0), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_loadbalancing"), "=", 0));
		LogicalConstraintFactory.ifThen(IntConstraintFactory.arithm(cl_gcp_loadbalancing, "=", 1), IntConstraintFactory.arithm(featureAttrinteroperability.get("cl_gcp_loadbalancing"), "!=", 0));
	}

	private static IntVar[] getFeatureVars(int contFeatures){
		IntVar[] featureVars = new IntVar[contFeatures];
		Variable[] varsSolver = solver.getVars();
		int index = 0;
		for(int i = 0; i < varsSolver.length; i++) {
			Variable current = varsSolver[i];
			if(current.getName().startsWith("feature_")) {
				featureVars[index] = (IntVar) current;
				index++;
			}
		}

		return featureVars;
	}
}


