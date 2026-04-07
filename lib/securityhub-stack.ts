import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as securityhub from 'aws-cdk-lib/aws-securityhub';

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
export class SecurityHubStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Habilitar Security Hub con los estándares por defecto de AWS.
    //
    // enableDefaultStandards: true  → habilita FSBP + CIS automáticamente.
    //   ⚠️  enableDefaultStandards: false puede dejar Security Hub en estado
    //       "no configurado" en la consola, aunque el recurso exista en CF.
    //
    // autoEnableControls: true → los nuevos controles que AWS publique
    //   en estándares activos se habilitan automáticamente.
    new securityhub.CfnHub(this, 'SecurityHub', {
      enableDefaultStandards: true,
      autoEnableControls: true,
    });
  }
}
