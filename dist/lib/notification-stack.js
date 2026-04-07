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
exports.NotificationStack = void 0;
const cdk = __importStar(require("aws-cdk-lib"));
const sns = __importStar(require("aws-cdk-lib/aws-sns"));
const subscriptions = __importStar(require("aws-cdk-lib/aws-sns-subscriptions"));
const config_1 = require("./config");
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
class NotificationStack extends cdk.Stack {
    constructor(scope, id, props) {
        super(scope, id, props);
        // Topic SNS dedicado para alertas de incidentes de seguridad
        const alertTopic = new sns.Topic(this, 'SecurityAlertTopic', {
            topicName: 'incident-response-alerts',
            displayName: 'Alertas de Incidentes de Seguridad AWS',
        });
        // Suscripción por email para notificaciones inmediatas al equipo de seguridad
        // Nota: el email se confirma manualmente una sola vez después del primer deploy
        alertTopic.addSubscription(new subscriptions.EmailSubscription(config_1.config.alertEmail));
        this.topicArn = alertTopic.topicArn;
        // Exportar ARN para uso en otros stacks y scripts de operación
        new cdk.CfnOutput(this, 'SNSTopicArn', {
            value: this.topicArn,
            description: 'ARN del topic SNS para alertas de seguridad',
            exportName: 'IncidentResponseSNSTopicArn',
        });
    }
}
exports.NotificationStack = NotificationStack;
