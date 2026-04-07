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
 *   6. EC2DemoStack      — instancia víctima para el demo en vivo (independiente)
 *
 * Desplegar todo de una vez:
 *   cdk deploy --all --require-approval never
 */

import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { GuardDutyStack } from '../lib/guardduty-stack';
import { CloudTrailStack } from '../lib/cloudtrail-stack';
import { SecurityHubStack } from '../lib/securityhub-stack';
import { NotificationStack } from '../lib/notification-stack';
import { ResponseStack } from '../lib/response-stack';
import { EC2DemoStack } from '../lib/ec2-demo-stack';
import { config } from '../lib/config';

const app = new cdk.App();

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: config.region,
};

// ── Stack 1: GuardDuty — Detección de amenazas con ML ─────────────────────
const guarddutyStack = new GuardDutyStack(app, 'GuardDutyStack', {
  env,
  description:
    'GuardDuty detector con protecciones S3, EKS y Malware habilitadas',
});

// ── Stack 2: CloudTrail — Auditoría multi-región ────────────────────────────
const cloudtrailStack = new CloudTrailStack(app, 'CloudTrailStack', {
  env,
  description:
    'CloudTrail multi-región con S3 (RETAIN) y CloudWatch Logs',
});

// ── Stack 3: Security Hub — Agregación y normalización de hallazgos ─────────
const securityHubStack = new SecurityHubStack(app, 'SecurityHubStack', {
  env,
  description:
    'Security Hub con estándar AWS Foundational Security Best Practices',
});
// Security Hub debe habilitarse después de GuardDuty para
// recibir correctamente sus hallazgos desde el inicio
securityHubStack.addDependency(guarddutyStack);

// ── Stack 4: Notificaciones — SNS para alertas de email ────────────────────
const notificationStack = new NotificationStack(app, 'NotificationStack', {
  env,
  description: 'Topic SNS con suscripción email para alertas de seguridad',
});

// ── Stack 5: Respuesta — EventBridge + Lambda de aislamiento ───────────────
const responseStack = new ResponseStack(app, 'ResponseStack', {
  env,
  description:
    'Regla EventBridge + Lambda de aislamiento automático de recursos',
  snsTopicArn: notificationStack.topicArn,
});
// La Lambda necesita SecurityHub activo y el topic SNS creado
responseStack.addDependency(securityHubStack);
responseStack.addDependency(notificationStack);

// ── Stack 6: EC2 Demo — Instancia víctima para el demo en vivo ─────────────
// Independiente de los stacks de seguridad. Crea una instancia t3.micro
// en el VPC por defecto que simulate.sh usa como blanco real del aislamiento.
new EC2DemoStack(app, 'EC2DemoStack', {
  env,
  description: 'Instancia EC2 víctima para demostrar el aislamiento automático en vivo',
});

app.synth();
