import groups.BAT
import groups.Integration
import groups.PolicyEnforcement
import objects.Deployment
import org.junit.experimental.categories.Category
import stackrox.generated.PolicyServiceOuterClass.EnforcementAction

class Enforcement extends BaseSpecification {
    private final static String CONTAINER_PORT_22_POLICY = "Container Port 22"

    @Category([BAT, PolicyEnforcement])
    def "Test Kill Enforcement"() {
        // This test only tests enforcement by directly telling Central to kill
        // a specific pod/container.
        //
        // Need to add a test using policy violation once piped
        //
        // THIS TEST SHOULD BE REMOVED IF THE ENFORCEMENT API IS REMOVED

        given:
        "Create Deployment to test kill enforcement"
        Deployment d = new Deployment()
                .setName("kill-enforcement")
                .setImage("nginx")
                .addPort(80)
                .addLabel("app", "kill-enforcement")
        orchestrator.createDeployment(d)

        when:
        "trigger kill enforcement on container"
        assert d.pods.size() > 0
        Services.applyKillEnforcement(
                d.pods.get(0).getPodId(),
                d.namespace,
                d.pods.get(0).containerIds.get(0))

        then:
        "check container was killed"
        assert orchestrator.wasContainerKilled(d.pods.get(0).name)

        cleanup:
        "remove deployment"
        orchestrator.deleteDeployment(d.name)
    }

    @Category([PolicyEnforcement])
    def "Test Scale-down Enforcement"() {
        // This test only tests enforcement by directly telling Central to scale-down
        // a specific deployment.
        //
        // THIS TEST SHOULD BE REMOVED IF THE ENFORCEMENT API IS REMOVED

        given:
        "Create Deployment to test scale-down enforcement"
        Deployment d = new Deployment()
                .setName("scale-down-enforcement")
                .setImage("nginx")
                .addPort(80)
                .addLabel("app", "scale-down-enforcement")
        orchestrator.createDeployment(d)

        when:
        "trigger scale-down enforcement on container"
        Services.applyScaleDownEnforcement(d)

        then:
        "check container was scaled-down to 0 replicas"
        assert orchestrator.getDeploymentReplicaCount(d) == 0

        cleanup:
        "remove deployment"
        orchestrator.deleteDeployment(d.name)
    }

    @Category([PolicyEnforcement])
    def "Test Node Constraint Enforcement"() {
        // This test only tests enforcement by directly telling Central to apply unsatisfiable
        // node constraint to a specific deployment.
        //
        // THIS TEST SHOULD BE REMOVED IF THE ENFORCEMENT API IS REMOVED

        given:
        "Create Deployment to test node constraint enforcement"
        Deployment d = new Deployment()
                .setName("node-constraint-enforcement")
                .setImage("nginx")
                .addPort(80)
                .addLabel("app", "node-constraint-enforcement")
        orchestrator.createDeployment(d)

        when:
        "trigger node constraint enforcement on container"
        Services.applyNodeConstraintEnforcement(d)
        sleep 3000 // add sleep here to make sure node constraint propogates

        then:
        "check deployment set with unsatisfiable node constraint, and unavailable nodes = desired nodes"
        assert orchestrator.getDeploymentNodeSelectors(d) != null
        assert orchestrator.getDeploymentUnavailableReplicaCount(d) ==
                orchestrator.getDeploymentReplicaCount(d)

        cleanup:
        "remove deployment"
        orchestrator.deleteDeployment(d.name)
    }

    @Category([BAT, Integration, PolicyEnforcement])
    def "Test Scale-down Enforcement - Integration"() {
        // This test verifies enforcement by triggering a policy violation on a policy
        // that is configured for scale-down enforcement

        given:
        "Add scale-down enforcement to an existing policy"
        def startEnforcements = Services.updatePolicyEnforcement(
                CONTAINER_PORT_22_POLICY,
                [EnforcementAction.SCALE_TO_ZERO_ENFORCEMENT,]
        )

        when:
        "Create Deployment to test scale-down enforcement"
        Deployment d = new Deployment()
                .setName("scale-down-enforcement-int")
                .setImage("nginx")
                .addPort(22)
                .addLabel("app", "scale-down-enforcement-int")
                .setSkipReplicaWait(true)
        orchestrator.createDeployment(d)

        then:
        "check deployment was scaled-down to 0 replicas"
        assert orchestrator.getDeploymentReplicaCount(d) == 0

        cleanup:
        "restore enforcement state of policy and remove deployment"
        Services.updatePolicyEnforcement(CONTAINER_PORT_22_POLICY, startEnforcements)
        orchestrator.deleteDeployment(d.name)
    }

    @Category([BAT, Integration, PolicyEnforcement])
    def "Test Node Constraint Enforcement - Integration"() {
        // This test verifies enforcement by triggering a policy violation on a policy
        // that is configured for node constraint enforcement

        given:
        "Add node constraint enforcement to an existing policy"
        def startEnforcements = Services.updatePolicyEnforcement(
                CONTAINER_PORT_22_POLICY,
                [EnforcementAction.UNSATISFIABLE_NODE_CONSTRAINT_ENFORCEMENT,]
        )

        when:
        "Create Deployment to test node constraint enforcement"
        Deployment d = new Deployment()
                .setName("node-constraint-enforcement-int")
                .setImage("nginx")
                .addPort(22)
                .addLabel("app", "node-constraint-enforcement-int")
                .setSkipReplicaWait(true)
        orchestrator.createDeployment(d)

        then:
        "check deployment set with unsatisfiable node constraint, and unavailable nodes = desired nodes"
        assert orchestrator.getDeploymentNodeSelectors(d) != null
        assert orchestrator.getDeploymentUnavailableReplicaCount(d) ==
                orchestrator.getDeploymentReplicaCount(d)

        cleanup:
        "restore enforcement state of policy and remove deployment"
        Services.updatePolicyEnforcement(CONTAINER_PORT_22_POLICY, startEnforcements)
        orchestrator.deleteDeployment(d.name)
    }
}
