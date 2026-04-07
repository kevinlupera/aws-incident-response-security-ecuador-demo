import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
/**
 * Stack de AWS Security Hub.
 *
 * Security Hub actúa como el SIEM nativo de AWS:
 *   - Agrega hallazgos de GuardDuty, Inspector, Macie, Firewall Manager, etc.
 *   - Normaliza todos los hallazgos al formato ASFF (Amazon Security Finding Format)
 *   - Evalúa controles de seguridad contra estándares como FSBP y CIS
 *
 * IMPORTANTE: Este stack tiene addDependency(GuardDutyStack) en app.ts
 *             para garantizar que GuardDuty exista antes de que Security Hub
 *             intente recibir sus hallazgos.
 *
 * enableDefaultStandards: true activa automáticamente:
 *   - AWS Foundational Security Best Practices (FSBP) v1.0.0 → 300+ controles
 *   - CIS AWS Foundations Benchmark v1.2.0
 */
export declare class SecurityHubStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps);
}
