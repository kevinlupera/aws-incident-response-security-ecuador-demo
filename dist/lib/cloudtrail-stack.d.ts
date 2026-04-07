import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
/**
 * Stack de CloudTrail para auditoría multi-región.
 *
 * Registra TODOS los API calls de AWS en la cuenta y los almacena en:
 *   1. S3 (retención permanente) — para análisis forense histórico
 *   2. CloudWatch Logs (retención 1 año) — para alertas en tiempo real
 *
 * RemovalPolicy.RETAIN en el bucket garantiza que los logs de auditoría
 * nunca se eliminen, incluso al hacer `cdk destroy`.
 */
export declare class CloudTrailStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps);
}
