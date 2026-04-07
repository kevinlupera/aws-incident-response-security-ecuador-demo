import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';
import { config } from './config';

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
export class GuardDutyStack extends cdk.Stack {
  /** ID del detector de GuardDuty para referencia en scripts externos */
  public readonly detectorId: string;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Construir lista de features habilitados según configuración
    const features: guardduty.CfnDetector.CFNFeatureConfigurationProperty[] =
      [];

    if (config.featureFlags.enableS3Protection) {
      features.push({
        name: 'S3_DATA_EVENTS',
        status: 'ENABLED',
      });
    }

    if (config.featureFlags.enableEKSProtection) {
      features.push({
        name: 'EKS_AUDIT_LOGS',
        status: 'ENABLED',
      });
    }

    if (config.featureFlags.enableMalwareProtection) {
      features.push({
        name: 'EBS_MALWARE_PROTECTION',
        status: 'ENABLED',
      });
    }

    // Crear el detector de GuardDuty
    // findingPublishingFrequency controla cada cuánto se envían los hallazgos
    // a EventBridge (FIFTEEN_MINUTES para demos, SIX_HOURS para producción)
    const detector = new guardduty.CfnDetector(this, 'GuardDutyDetector', {
      enable: true,
      findingPublishingFrequency:
        config.featureFlags.findingPublishingFrequency,
      features,
    });

    this.detectorId = detector.ref;

    // Exportar el ID del detector — lo usará simulate.sh automáticamente
    new cdk.CfnOutput(this, 'DetectorId', {
      value: this.detectorId,
      description: 'ID del detector de GuardDuty',
      exportName: 'GuardDutyDetectorId',
    });
  }
}
