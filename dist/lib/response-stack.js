"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ResponseStack = void 0;
const cdk = __importStar(require("aws-cdk-lib"));
const events = __importStar(require("aws-cdk-lib/aws-events"));
const targets = __importStar(require("aws-cdk-lib/aws-events-targets"));
const lambda = __importStar(require("aws-cdk-lib/aws-lambda"));
const lambdaNodejs = __importStar(require("aws-cdk-lib/aws-lambda-nodejs"));
const iam = __importStar(require("aws-cdk-lib/aws-iam"));
const logs = __importStar(require("aws-cdk-lib/aws-logs"));
const path = __importStar(require("path"));
const config_1 = require("./config");
/**
 * Stack de Respuesta Automatizada a Incidentes.
 *
 * Implementa el núcleo del pipeline de respuesta automática:
 *
 *   GuardDuty Finding
 *        ↓
 *   Security Hub (normalización ASFF)
 *        ↓
 *   EventBridge Rule (filtra severidad >= 7)
 *        ↓
 *   Lambda: isolate-resource
 *     ├── EC2 Instance → Security Group de cuarentena (sin reglas)
 *     ├── IAM AccessKey → Política DenyAll adjuntada al usuario
 *     └── SNS → Email de alerta con todos los detalles
 *
 * IMPORTANTE: addDependency(SecurityHubStack) y addDependency(NotificationStack)
 *             se establecen en bin/app.ts para garantizar el orden de despliegue.
 *
 * IAM Role con mínimo privilegio: solo los permisos estrictamente necesarios
 * para EC2 quarantine, IAM policy attachment y SNS publish.
 */
class ResponseStack extends cdk.Stack {
    constructor(scope, id, props) {
        super(scope, id, props);
        // ── IAM Role para la Lambda de aislamiento ────────────────────────────
        // Principio de mínimo privilegio: cada permiso tiene una justificación
        const lambdaRole = new iam.Role(this, 'IsolationLambdaRole', {
            assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
            roleName: 'incident-response-lambda-role',
            description: 'Rol con mínimo privilegio para la Lambda de aislamiento automático',
            managedPolicies: [
                // Permite escribir logs en CloudWatch (requerido para toda Lambda)
                iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
            ],
        });
        // Permisos EC2: necesarios para crear SG de cuarentena y reasignarlo
        // a la instancia comprometida. EC2 requiere '*' en resource para describe/create.
        lambdaRole.addToPolicy(new iam.PolicyStatement({
            sid: 'EC2QuarantinePermissions',
            effect: iam.Effect.ALLOW,
            actions: [
                'ec2:CreateSecurityGroup',
                'ec2:DescribeInstances',
                'ec2:DescribeSecurityGroups',
                'ec2:RevokeSecurityGroupEgress',
                'ec2:ModifyInstanceAttribute',
                'ec2:CreateTags',
            ],
            resources: ['*'],
        }));
        // Permisos IAM: necesarios para crear y adjuntar política DenyAll
        // al usuario con Access Key comprometida
        lambdaRole.addToPolicy(new iam.PolicyStatement({
            sid: 'IAMQuarantinePermissions',
            effect: iam.Effect.ALLOW,
            actions: [
                'iam:CreatePolicy',
                'iam:AttachUserPolicy',
                'iam:GetUser',
            ],
            resources: ['*'],
        }));
        // Permisos SNS: solo publish al topic de alertas (no a otros topics)
        lambdaRole.addToPolicy(new iam.PolicyStatement({
            sid: 'SNSPublishAlerts',
            effect: iam.Effect.ALLOW,
            actions: ['sns:Publish'],
            resources: [props.snsTopicArn], // Acceso restringido al topic específico
        }));
        // ── Log Group explícito para la Lambda ────────────────────────────────
        // Se crea antes que la función para evitar el error ResourceNotFoundException
        // cuando CloudWatch Logs Insights u otras herramientas intentan acceder
        // al grupo antes de la primera invocación de la Lambda.
        const logGroup = new logs.LogGroup(this, 'IsolationLambdaLogGroup', {
            logGroupName: '/aws/lambda/incident-response-isolate-resource',
            retention: logs.RetentionDays.ONE_MONTH,
            removalPolicy: cdk.RemovalPolicy.DESTROY,
        });
        // ── Lambda de aislamiento (NodejsFunction = bundling automático con esbuild) ──
        // NodejsFunction compila y empaqueta el TypeScript en tiempo de síntesis CDK.
        // Runtime NODEJS_22_X: la versión LTS más reciente disponible en Lambda.
        const isolationLambda = new lambdaNodejs.NodejsFunction(this, 'IsolationLambda', {
            runtime: lambda.Runtime.NODEJS_22_X,
            entry: path.join(__dirname, '../lambdas/isolate-resource/index.ts'),
            handler: 'handler',
            role: lambdaRole,
            timeout: cdk.Duration.seconds(60),
            memorySize: 256,
            functionName: 'incident-response-isolate-resource',
            logGroup,
            description: 'Aisla automáticamente recursos comprometidos detectados por GuardDuty',
            environment: {
                SNS_TOPIC_ARN: props.snsTopicArn,
                MIN_SEVERITY: String(config_1.config.minSeverityToIsolate),
                AWS_REGION_NAME: this.region,
            },
            bundling: {
                // Incluir el SDK v3 en el bundle (no viene pre-instalado en Node 22)
                externalModules: [],
                minify: false, // false para facilitar debugging en el demo
                sourceMap: true,
            },
        });
        // ── Regla de EventBridge ───────────────────────────────────────────────
        //
        // Filtra hallazgos de GuardDuty con severidad >= minSeverityToIsolate (7).
        //
        // El patrón usa content-based filtering de EventBridge:
        //   { "numeric": [">=", 7] } → filtra valores numéricos mayores o iguales a 7
        //
        // Severidades de GuardDuty:
        //   LOW:      1.0 – 3.9  → no dispara la regla
        //   MEDIUM:   4.0 – 6.9  → no dispara la regla
        //   HIGH:     7.0 – 8.9  → DISPARA ← para el demo
        //   CRITICAL: 9.0 – 10.0 → DISPARA
        const guardDutyRule = new events.Rule(this, 'HighSeverityFindingRule', {
            ruleName: 'guardduty-high-severity-findings',
            description: 'Dispara respuesta automática ante hallazgos de GuardDuty de alta severidad (>=7)',
            eventPattern: {
                source: ['aws.guardduty'],
                detailType: ['GuardDuty Finding'],
                detail: {
                    severity: [{ numeric: ['>=', config_1.config.minSeverityToIsolate] }],
                },
            },
        });
        // Agregar Lambda como destino con reintentos
        // retryAttempts: 2 → si la Lambda falla, EventBridge reintenta 2 veces
        guardDutyRule.addTarget(new targets.LambdaFunction(isolationLambda, {
            retryAttempts: 2,
        }));
    }
}
exports.ResponseStack = ResponseStack;
