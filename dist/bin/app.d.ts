#!/usr/bin/env node
/**
 * Punto de entrada de la aplicación CDK.
 *
 * Demo: "Nadie Apretó un Botón: Respuesta Automática a Incidentes con AWS Nativo"
 * Evento: AWS Security Community Ecuador
 *
 * Pipeline de respuesta automática:
 *   GuardDuty → Security Hub → EventBridge → Lambda → [EC2/IAM aislado + SNS alert]
 *
 * Orden de despliegue (respeta las dependencias):
 *   1. GuardDutyStack    — habilita detección de amenazas
 *   2. CloudTrailStack   — auditoría y logs (independiente)
 *   3. SecurityHubStack  — agrega hallazgos (depende de GuardDuty)
 *   4. NotificationStack — topic SNS (independiente)
 *   5. ResponseStack     — EventBridge + Lambda (depende de SecurityHub + SNS)
 *
 * Desplegar todo de una vez:
 *   cdk deploy --all --require-approval never
 */
import 'source-map-support/register';
