import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as logs from 'aws-cdk-lib/aws-logs';

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
export class CloudTrailStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ── Bucket S3 para logs de CloudTrail ─────────────────────────────────
    // RETAIN: los logs de auditoría son evidencia forense, jamás se eliminan
    const trailBucket = new s3.Bucket(this, 'CloudTrailBucket', {
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          id: 'ArchivarEnGlacierDespues365Dias',
          enabled: true,
          transitions: [
            {
              // Después de 1 año, mover a Glacier para reducir costos
              storageClass: s3.StorageClass.GLACIER,
              transitionAfter: cdk.Duration.days(365),
            },
          ],
        },
      ],
    });

    // ── CloudWatch Logs para análisis en tiempo real ───────────────────────
    const logGroup = new logs.LogGroup(this, 'CloudTrailLogGroup', {
      logGroupName: '/aws/cloudtrail/incident-response',
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ── Trail multi-región ─────────────────────────────────────────────────
    // isMultiRegionTrail: captura eventos de TODAS las regiones en un solo trail
    // includeGlobalServiceEvents: incluye IAM, STS, CloudFront (servicios globales)
    // enableFileValidation: permite verificar integridad de los logs con SHA-256
    const trail = new cloudtrail.Trail(this, 'IncidentResponseTrail', {
      bucket: trailBucket,
      cloudWatchLogGroup: logGroup,
      sendToCloudWatchLogs: true,
      cloudWatchLogsRetention: logs.RetentionDays.ONE_YEAR,
      isMultiRegionTrail: true,
      includeGlobalServiceEvents: true,
      enableFileValidation: true,
      trailName: 'incident-response-trail',
    });

    // Capturar eventos de datos S3 y Lambda (management events ya están incluidos)
    trail.logAllS3DataEvents();
    trail.logAllLambdaDataEvents();
  }
}
