import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
/**
 * Stack que habilita Amazon GuardDuty con protecciones adicionales.
 *
 * GuardDuty analiza continuamente:
 *   - AWS CloudTrail Events (API calls sospechosos)
 *   - VPC Flow Logs (tráfico de red anómalo)
 *   - DNS Logs (comunicación con dominios maliciosos)
 *   - S3 Data Events (accesos indebidos a buckets)
 *   - EKS Audit Logs (actividad maliciosa en Kubernetes)
 *
 * Exporta el DetectorId para uso en scripts de simulación.
 */
export declare class GuardDutyStack extends cdk.Stack {
    /** ID del detector de GuardDuty para referencia en scripts externos */
    readonly detectorId: string;
    constructor(scope: Construct, id: string, props?: cdk.StackProps);
}
