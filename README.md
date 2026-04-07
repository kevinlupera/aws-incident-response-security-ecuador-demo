# 🔐 aws-incident-response

> **"Nadie Apretó un Botón: Respuesta Automática a Incidentes con AWS Nativo"**
>
> Demo presentado en AWS Security Community Ecuador

Pipeline serverless que detecta, aísla y notifica automáticamente cuando GuardDuty encuentra una amenaza de alta severidad — sin intervención humana.

---

## Diagrama de Arquitectura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Pipeline de Respuesta Automática                         │
│                                                                               │
│  ┌────────────┐     ┌──────────────┐     ┌─────────────────────────────┐    │
│  │            │     │              │     │      EventBridge Rule        │    │
│  │ GuardDuty  │────▶│ Security Hub │────▶│  severity >= 7 (HIGH/CRIT)  │    │
│  │            │     │     ASFF     │     │  source: aws.guardduty       │    │
│  └────────────┘     └──────────────┘     └──────────────┬──────────────┘    │
│                                                          │                    │
│                                                          ▼                    │
│                                              ┌───────────────────────┐       │
│                                              │  Lambda: isolate-     │       │
│                                              │  resource (Node 22)   │       │
│                                              └─────────┬─────────────┘       │
│                                                        │                      │
│                              ┌─────────────────────────┼────────────────┐    │
│                              │                         │                │    │
│                              ▼                         ▼                ▼    │
│                   ┌──────────────────┐    ┌────────────────────┐  ┌───────┐ │
│                   │  EC2 Instance    │    │   IAM AccessKey    │  │  SNS  │ │
│                   │  → SG Cuarentena│    │   → Policy DenyAll │  │ Email │ │
│                   │  (sin reglas)   │    │   (usuario aislado) │  │ Alert │ │
│                   └──────────────────┘    └────────────────────┘  └───────┘ │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │  CloudTrail → S3 (RETAIN + Glacier 365d) + CloudWatch Logs (1 año) │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Servicios AWS Utilizados

| Servicio               | Función                                              | Stack CDK          |
|------------------------|------------------------------------------------------|--------------------|
| Amazon GuardDuty       | Detección de amenazas con ML + threat intelligence   | `GuardDutyStack`   |
| AWS CloudTrail         | Auditoría de API calls multi-región                  | `CloudTrailStack`  |
| AWS Security Hub       | Agregación y normalización de hallazgos (ASFF)       | `SecurityHubStack` |
| Amazon SNS             | Notificaciones por email al equipo de seguridad      | `NotificationStack`|
| Amazon EventBridge     | Enrutamiento de eventos por severidad (>= 7)         | `ResponseStack`    |
| AWS Lambda             | Aislamiento automático de recursos comprometidos     | `ResponseStack`    |
| Amazon EC2 (SG)        | Security Group de cuarentena sin reglas              | Lambda             |
| AWS IAM                | Política DenyAll para Access Keys comprometidas      | Lambda             |
| Amazon S3              | Almacenamiento de logs CloudTrail (RETAIN permanente)| `CloudTrailStack`  |
| Amazon CloudWatch Logs | Logs en tiempo real de CloudTrail y Lambda           | Ambos stacks       |

---

## Estructura del Repositorio

```
aws-incident-response/
├── bin/
│   └── app.ts                    # Punto de entrada CDK — instancia todos los stacks
├── lib/
│   ├── config.ts                 # ⚙️  Configuración central (email, región, severidad)
│   ├── guardduty-stack.ts        # Stack: detector + protecciones S3/EKS/Malware
│   ├── cloudtrail-stack.ts       # Stack: trail multi-región + S3 + CloudWatch
│   ├── securityhub-stack.ts      # Stack: Security Hub + estándar FSBP
│   ├── notification-stack.ts     # Stack: SNS topic + suscripción email
│   └── response-stack.ts         # Stack: EventBridge + Lambda + IAM Role
├── lambdas/
│   └── isolate-resource/
│       └── index.ts              # Lambda handler — aislamiento EC2/IAM + SNS
├── scripts/
│   └── simulate.sh               # Script de simulación con GuardDuty sample findings
├── package.json
├── tsconfig.json
├── cdk.json
└── README.md
```

---

## Pre-requisitos de Configuración

### 1. Configurar el email de alertas

Edita `lib/config.ts` y cambia el email:

```typescript
alertEmail: 'tu-email-real@example.com',  // ← Cambia esto
```

> **Importante:** Recibirás un email de confirmación de AWS SNS. Debes hacer clic en
> el enlace de confirmación antes de recibir alertas reales.

### 2. (Opcional) Ajustar la región

```typescript
region: 'us-east-1',  // Cambia si prefieres otra región
```

### 3. (Opcional) Ajustar severidad mínima de aislamiento

```typescript
minSeverityToIsolate: 7,  // 7 = HIGH, 9 = solo CRITICAL
```

### 4. Verificar pre-requisitos de AWS

```bash
# Verificar credenciales AWS activas
aws sts get-caller-identity

# Verificar que CDK esté instalado
cdk --version

# Si es la primera vez usando CDK en esta cuenta/región:
cdk bootstrap
```

---

## Comandos de Despliegue

### Paso 1 — Instalar dependencias

```bash
npm install
```

### Paso 2 — Compilar TypeScript

```bash
npm run build
```

### Paso 3 — Desplegar toda la infraestructura

```bash
cdk deploy --all --require-approval never
```

> El despliegue tarda aproximadamente 3–5 minutos. Al finalizar verás los outputs:
> - `GuardDutyStack.DetectorId` — ID del detector de GuardDuty
> - `NotificationStack.SNSTopicArn` — ARN del topic SNS

---

## Cómo Ejecutar la Simulación

```bash
# Dar permisos de ejecución (solo la primera vez)
chmod +x scripts/simulate.sh

# Ejecutar simulación
./scripts/simulate.sh
```

El script automáticamente:
1. Detecta el ID del detector de GuardDuty
2. Crea un hallazgo de muestra tipo `UnauthorizedAccess:IAMUser/MaliciousIPCaller`
3. Muestra qué observar y los tiempos estimados de propagación
4. Imprime comandos útiles para monitorear el pipeline en tiempo real

### Tiempos estimados de propagación

| Etapa            | Servicio          | Tiempo estimado |
|------------------|-------------------|-----------------|
| Hallazgo creado  | GuardDuty         | Inmediato       |
| Normalización    | Security Hub      | 1–2 minutos     |
| Regla disparada  | EventBridge       | 2–3 minutos     |
| Lambda ejecutada | Lambda + CloudWatch| 3–5 minutos    |
| Email recibido   | SNS               | 5–7 minutos     |

---

## Teardown (Eliminar recursos)

```bash
# Elimina todos los stacks (excepto el bucket S3 de CloudTrail por RETAIN)
cdk destroy --all

# Para eliminar el bucket S3 manualmente (contiene logs de auditoría):
# Ir a Consola AWS → S3 → Vaciar bucket → Eliminar bucket
```

> **Nota:** El bucket S3 de CloudTrail tiene `RemovalPolicy.RETAIN` por diseño.
> Los logs de auditoría son evidencia forense y no deben eliminarse automáticamente.

---

## Tabla de Severidades de GuardDuty

| Nivel    | Rango      | Color  | ¿Dispara pipeline? | Ejemplo de amenaza                              |
|----------|------------|--------|--------------------|------------------------------------------------|
| LOW      | 1.0 – 3.9  | 🟢     | No                 | Puerto escaneo desde IP conocida               |
| MEDIUM   | 4.0 – 6.9  | 🟡     | No                 | Acceso a S3 desde IP anónima                   |
| HIGH     | 7.0 – 8.9  | 🔴     | **Sí** (default)   | API call desde IP maliciosa conocida           |
| CRITICAL | 9.0 – 10.0 | 🚨     | **Sí**             | Exfiltración activa de credenciales            |

La severidad mínima para disparar el pipeline se configura en `lib/config.ts`.

---

## Notas del Demo

- Los **sample findings** de GuardDuty son hallazgos sintéticos — no representan amenazas reales en tu cuenta
- El aislamiento automático es para **demostración** — en producción implementar aprobación manual para alta severidad
- Para producción, considera habilitar **GuardDuty Multi-Account** y **Security Hub Organizations**
- Los logs de CloudTrail con `RETAIN` aseguran que la evidencia forense persista incluso tras un `cdk destroy`

---

*Generado para la charla "Nadie Apretó un Botón: Respuesta Automática a Incidentes con AWS Nativo"*
*AWS Security Community Ecuador*
