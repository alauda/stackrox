package common

class Constants {
    static final ORCHESTRATOR_NAMESPACE = "qa"
    static final SCHEDULES_SUPPORTED = false
    static final CHECK_CVES_IN_COMPLIANCE = false
    static final RUN_FLAKEY_TESTS = false
    static final Map<String, String> CSV_COLUMN_MAPPING = [
            "Standard" : "standard",
            "Cluster" : "cluster",
            "Namespace" : "namespace",
            "Object Type" : "objectType",
            "Object Name" : "objectName",
            "Control" : "control",
            "Control Description" : "controlDescription",
            "State" : "state",
            "Evidence" : "evidence",
            "Assessment Time" : "timestamp",
    ]
}
