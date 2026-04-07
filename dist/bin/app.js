#!/usr/bin/env node
"use strict";
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
require("source-map-support/register");
const cdk = __importStar(require("aws-cdk-lib"));
const guardduty_stack_1 = require("../lib/guardduty-stack");
const cloudtrail_stack_1 = require("../lib/cloudtrail-stack");
const securityhub_stack_1 = require("../lib/securityhub-stack");
const notification_stack_1 = require("../lib/notification-stack");
const response_stack_1 = require("../lib/response-stack");
const config_1 = require("../lib/config");
const app = new cdk.App();
const env = {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: config_1.config.region,
};
// ── Stack 1: GuardDuty — Detección de amenazas con ML ─────────────────────
const guarddutyStack = new guardduty_stack_1.GuardDutyStack(app, 'GuardDutyStack', {
    env,
    description: 'GuardDuty detector con protecciones S3, EKS y Malware habilitadas',
});
// ── Stack 2: CloudTrail — Auditoría multi-región ────────────────────────────
const cloudtrailStack = new cloudtrail_stack_1.CloudTrailStack(app, 'CloudTrailStack', {
    env,
    description: 'CloudTrail multi-región con S3 (RETAIN) y CloudWatch Logs',
});
// ── Stack 3: Security Hub — Agregación y normalización de hallazgos ─────────
const securityHubStack = new securityhub_stack_1.SecurityHubStack(app, 'SecurityHubStack', {
    env,
    description: 'Security Hub con estándar AWS Foundational Security Best Practices',
});
// Security Hub debe habilitarse después de GuardDuty para
// recibir correctamente sus hallazgos desde el inicio
securityHubStack.addDependency(guarddutyStack);
// ── Stack 4: Notificaciones — SNS para alertas de email ────────────────────
const notificationStack = new notification_stack_1.NotificationStack(app, 'NotificationStack', {
    env,
    description: 'Topic SNS con suscripción email para alertas de seguridad',
});
// ── Stack 5: Respuesta — EventBridge + Lambda de aislamiento ───────────────
const responseStack = new response_stack_1.ResponseStack(app, 'ResponseStack', {
    env,
    description: 'Regla EventBridge + Lambda de aislamiento automático de recursos',
    snsTopicArn: notificationStack.topicArn,
});
// La Lambda necesita SecurityHub activo y el topic SNS creado
responseStack.addDependency(securityHubStack);
responseStack.addDependency(notificationStack);
app.synth();
