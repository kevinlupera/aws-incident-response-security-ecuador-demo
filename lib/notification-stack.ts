import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import { config } from './config';

/**
 * Stack de Notificaciones con Amazon SNS.
 *
 * Publica alertas formateadas cuando se detecta y aísla un recurso comprometido.
 * El mensaje incluye: tipo de amenaza, severidad, región, cuenta, recurso,
 * resultado del aislamiento y próximos pasos recomendados.
 *
 * ⚠️  IMPORTANTE: Al hacer `cdk deploy`, AWS enviará un email de confirmación
 *     a la dirección configurada en config.alertEmail. Debes confirmar la
 *     suscripción antes de recibir alertas.
 *
 * El topicArn se exporta para que ResponseStack pueda otorgar permisos
 * a la Lambda de aislamiento.
 */
export class NotificationStack extends cdk.Stack {
  /** ARN del topic SNS — usado por ResponseStack para configurar la Lambda */
  public readonly topicArn: string;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Topic SNS dedicado para alertas de incidentes de seguridad
    const alertTopic = new sns.Topic(this, 'SecurityAlertTopic', {
      topicName: 'incident-response-alerts',
      displayName: 'Alertas de Incidentes de Seguridad AWS',
    });

    // Suscripción por email para notificaciones inmediatas al equipo de seguridad
    // Nota: el email se confirma manualmente una sola vez después del primer deploy
    alertTopic.addSubscription(
      new subscriptions.EmailSubscription(config.alertEmail)
    );

    this.topicArn = alertTopic.topicArn;

    // Exportar ARN para uso en otros stacks y scripts de operación
    new cdk.CfnOutput(this, 'SNSTopicArn', {
      value: this.topicArn,
      description: 'ARN del topic SNS para alertas de seguridad',
      exportName: 'IncidentResponseSNSTopicArn',
    });
  }
}
