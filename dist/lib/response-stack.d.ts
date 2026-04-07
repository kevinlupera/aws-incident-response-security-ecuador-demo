import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
/**
 * Props extendidos para el ResponseStack.
 * Recibe el ARN del topic SNS desde NotificationStack.
 */
interface ResponseStackProps extends cdk.StackProps {
    snsTopicArn: string;
}
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
export declare class ResponseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: ResponseStackProps);
}
export {};
