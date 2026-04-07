import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
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
export declare class NotificationStack extends cdk.Stack {
    /** ARN del topic SNS — usado por ResponseStack para configurar la Lambda */
    readonly topicArn: string;
    constructor(scope: Construct, id: string, props?: cdk.StackProps);
}
