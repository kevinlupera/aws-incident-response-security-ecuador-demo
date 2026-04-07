/**
 * Lambda: isolate-resource
 *
 * Handler principal del pipeline de respuesta automática a incidentes.
 * Es invocada por EventBridge cuando GuardDuty detecta una amenaza
 * con severidad >= MIN_SEVERITY.
 *
 * Acciones según el tipo de recurso comprometido:
 *   - Instance   → Crea SG de cuarentena vacío en el mismo VPC y lo asigna
 *   - AccessKey  → Crea y adjunta política IAM de denegación total al usuario
 *   - (otros)    → Registra en logs y notifica sin acción de aislamiento
 *
 * Siempre publica en SNS con el resultado completo del incidente.
 */

import {
  EC2Client,
  CreateSecurityGroupCommand,
  DescribeInstancesCommand,
  DescribeSecurityGroupsCommand,
  RevokeSecurityGroupEgressCommand,
  ModifyInstanceAttributeCommand,
  CreateTagsCommand,
} from '@aws-sdk/client-ec2';
import {
  IAMClient,
  CreatePolicyCommand,
  AttachUserPolicyCommand,
} from '@aws-sdk/client-iam';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

// Clientes del SDK v3 — instanciados fuera del handler para reutilizar conexiones
const ec2Client = new EC2Client({});
const iamClient = new IAMClient({});
const snsClient = new SNSClient({});

// Variables de entorno inyectadas por ResponseStack
const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN!;
const MIN_SEVERITY = parseFloat(process.env.MIN_SEVERITY ?? '7');
const REGION = process.env.AWS_REGION_NAME ?? process.env.AWS_REGION ?? 'us-east-1';

// Tipos para el evento de GuardDuty via EventBridge
interface GuardDutyFinding {
  id: string;
  type: string;
  severity: number;
  accountId: string;
  region: string;
  resource?: {
    resourceType?: string;
    instanceDetails?: {
      instanceId?: string;
      vpcId?: string;
    };
    accessKeyDetails?: {
      userName?: string;
      accessKeyId?: string;
    };
  };
}

interface EventBridgeEvent {
  detail: GuardDutyFinding;
}

interface AlertParams {
  findingType: string;
  findingId: string;
  severity: number;
  region: string;
  accountId: string;
  resourceType: string;
  resourceId: string;
  isolationResult: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler principal
// ─────────────────────────────────────────────────────────────────────────────

export const handler = async (event: EventBridgeEvent): Promise<void> => {
  console.log('Evento recibido:', JSON.stringify(event, null, 2));

  const finding = event.detail;
  const { severity, type: findingType, accountId, region, id: findingId } = finding;
  const resourceType = finding.resource?.resourceType ?? 'Unknown';

  // Verificar severidad mínima — capa de defensa adicional al filtro de EventBridge
  if (severity < MIN_SEVERITY) {
    console.log(
      `Severidad ${severity} por debajo del umbral ${MIN_SEVERITY}. Omitiendo hallazgo ${findingId}.`
    );
    return;
  }

  console.log(
    `[INCIDENTE] Tipo: ${findingType} | Severidad: ${severity} | Recurso: ${resourceType}`
  );

  let isolationResult = 'Sin acción de aislamiento automático para este tipo de recurso';
  let resourceId = 'No disponible';

  try {
    if (resourceType === 'Instance') {
      // Aislar instancia EC2 comprometida
      const instanceId = finding.resource?.instanceDetails?.instanceId;
      resourceId = instanceId ?? 'ID de instancia no disponible';
      isolationResult = await isolateEC2Instance(instanceId, findingType);

    } else if (resourceType === 'AccessKey') {
      // Aislar Access Key de IAM comprometida
      const userName = finding.resource?.accessKeyDetails?.userName;
      const accessKeyId = finding.resource?.accessKeyDetails?.accessKeyId;
      resourceId = `Usuario: ${userName ?? 'N/A'} | AccessKey: ${accessKeyId ?? 'N/A'}`;
      isolationResult = await isolateIAMAccessKey(userName, accessKeyId);

    } else {
      // Tipo de recurso no soportado — solo notificar
      isolationResult = `Tipo de recurso "${resourceType}" no soportado para aislamiento automático. Requiere revisión manual.`;
      console.warn(isolationResult);
    }
  } catch (error) {
    // Capturar errores de aislamiento — siempre notificar aunque falle el aislamiento
    const errorMessage = error instanceof Error ? error.message : String(error);
    isolationResult = `ERROR durante el aislamiento: ${errorMessage}`;
    console.error('Error en aislamiento:', error);
  }

  // Publicar alerta en SNS con resultado completo (aislamiento exitoso o fallido)
  await publishAlert({
    findingType,
    findingId,
    severity,
    region,
    accountId,
    resourceType,
    resourceId,
    isolationResult,
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// Aislamiento de instancia EC2
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aísla una instancia EC2 comprometida mediante un Security Group de cuarentena.
 *
 * Pasos:
 *   1. Obtener el VPC ID de la instancia
 *   2. Crear un nuevo Security Group vacío en ese VPC (sin reglas = sin tráfico)
 *   3. Revocar la regla de egreso "allow all" que AWS crea por defecto
 *   4. Reemplazar todos los SGs de la instancia con el SG de cuarentena
 *
 * Resultado: la instancia queda completamente aislada de red,
 *            preservando el sistema de archivos para análisis forense.
 */
async function isolateEC2Instance(
  instanceId: string | undefined,
  findingType: string
): Promise<string> {
  if (!instanceId) {
    return 'No se pudo aislar: ID de instancia ausente en el hallazgo de GuardDuty';
  }

  console.log(`[EC2] Iniciando aislamiento de instancia: ${instanceId}`);

  // Paso 1: Obtener VPC ID de la instancia
  let describeResult;
  try {
    describeResult = await ec2Client.send(
      new DescribeInstancesCommand({ InstanceIds: [instanceId] })
    );
  } catch (err: any) {
    // InvalidInstanceID.NotFound ocurre con sample findings de GuardDuty
    // que usan IDs ficticios (ej: i-99999999). En producción indicaría
    // que la instancia ya fue terminada antes del aislamiento.
    if (err.Code === 'InvalidInstanceID.NotFound' || err.name === 'InvalidInstanceID.NotFound') {
      return `Instancia ${instanceId} no encontrada. Si es un hallazgo de muestra (sample finding), esto es esperado — en producción la instancia ya habría sido aislada.`;
    }
    throw err;
  }

  const instance = describeResult.Reservations?.[0]?.Instances?.[0];
  if (!instance) {
    return `Instancia ${instanceId} no encontrada (puede haber sido terminada antes del aislamiento)`;
  }

  const vpcId = instance.VpcId;
  if (!vpcId) {
    return `No se pudo determinar el VPC de la instancia ${instanceId}`;
  }

  // Paso 2: Crear Security Group de cuarentena (sin reglas = bloqueo total)
  const sgName = `quarantine-${instanceId}-${Date.now()}`;
  const createSGResult = await ec2Client.send(
    new CreateSecurityGroupCommand({
      GroupName: sgName,
      Description: `[AUTO-CUARENTENA] GuardDuty: ${findingType}`,
      VpcId: vpcId,
    })
  );

  const quarantineSGId = createSGResult.GroupId!;
  console.log(`[EC2] SG de cuarentena creado: ${quarantineSGId}`);

  // Etiquetar el SG para identificación y auditoría
  await ec2Client.send(
    new CreateTagsCommand({
      Resources: [quarantineSGId],
      Tags: [
        { Key: 'Name', Value: 'AUTO-QUARANTINE' },
        { Key: 'IncidentResponse', Value: 'Automated' },
        { Key: 'GuardDutyFinding', Value: findingType },
        { Key: 'IsolatedInstance', Value: instanceId },
        { Key: 'CreatedAt', Value: new Date().toISOString() },
      ],
    })
  );

  // Paso 3: Revocar la regla de egreso "allow all" que AWS agrega por defecto
  // Sin esto, la instancia podría seguir enviando datos hacia afuera
  const descSGResult = await ec2Client.send(
    new DescribeSecurityGroupsCommand({ GroupIds: [quarantineSGId] })
  );

  const sg = descSGResult.SecurityGroups?.[0];
  if (sg?.IpPermissionsEgress && sg.IpPermissionsEgress.length > 0) {
    await ec2Client.send(
      new RevokeSecurityGroupEgressCommand({
        GroupId: quarantineSGId,
        IpPermissions: sg.IpPermissionsEgress,
      })
    );
    console.log(`[EC2] Reglas de egreso revocadas del SG ${quarantineSGId}`);
  }

  // Paso 4: Reemplazar TODOS los SGs de la instancia con el SG de cuarentena
  // La instancia queda con un único SG sin ninguna regla (ingress ni egress)
  await ec2Client.send(
    new ModifyInstanceAttributeCommand({
      InstanceId: instanceId,
      Groups: [quarantineSGId],
    })
  );

  const result =
    `✅ Instancia ${instanceId} aislada exitosamente. ` +
    `SG de cuarentena: ${quarantineSGId} (sin reglas de ingreso/egreso). ` +
    `VPC: ${vpcId}`;
  console.log(`[EC2] ${result}`);
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Aislamiento de Access Key de IAM
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Aísla una Access Key de IAM comprometida adjuntando una política DenyAll.
 *
 * Pasos:
 *   1. Crear una política IAM inline con Effect: Deny para Action: * Resource: *
 *   2. Adjuntarla al usuario comprometido
 *
 * Resultado: el usuario no puede realizar ninguna acción en AWS,
 *            independientemente de sus políticas previas (Deny siempre gana).
 *            La Access Key sigue existente para análisis forense.
 */
async function isolateIAMAccessKey(
  userName: string | undefined,
  accessKeyId: string | undefined
): Promise<string> {
  if (!userName) {
    return 'No se pudo aislar: nombre de usuario ausente en el hallazgo de GuardDuty';
  }

  console.log(`[IAM] Iniciando aislamiento de usuario: ${userName} (AccessKey: ${accessKeyId})`);

  // Política de denegación total — Effect: Deny tiene prioridad sobre cualquier Allow
  const denyAllPolicy = {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DenyAllActionsQuarantine',
        Effect: 'Deny',
        Action: '*',
        Resource: '*',
      },
    ],
  };

  const policyName = `DenyAll-Quarantine-${userName}-${Date.now()}`;

  // Crear política de denegación en IAM
  const createPolicyResult = await iamClient.send(
    new CreatePolicyCommand({
      PolicyName: policyName,
      PolicyDocument: JSON.stringify(denyAllPolicy),
      Description: `[AUTO-CUARENTENA] AccessKey comprometida: ${accessKeyId ?? 'N/A'}`,
    })
  );

  const policyArn = createPolicyResult.Policy?.Arn;
  if (!policyArn) {
    return `Error al crear la política DenyAll para usuario ${userName}`;
  }

  console.log(`[IAM] Política DenyAll creada: ${policyArn}`);

  // Adjuntar política al usuario — a partir de este momento no puede hacer nada
  await iamClient.send(
    new AttachUserPolicyCommand({
      UserName: userName,
      PolicyArn: policyArn,
    })
  );

  const result =
    `✅ Usuario ${userName} aislado exitosamente. ` +
    `Política DenyAll adjuntada: ${policyArn}. ` +
    `La Access Key ${accessKeyId ?? 'N/A'} sigue activa para análisis forense.`;
  console.log(`[IAM] ${result}`);
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Publicación de alerta en SNS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Publica una alerta formateada en SNS con todos los detalles del incidente.
 * El mensaje está diseñado para ser legible tanto en email como en SMS.
 */
async function publishAlert(params: AlertParams): Promise<void> {
  const severityLabel = getSeverityLabel(params.severity);
  const consoleUrl = `https://console.aws.amazon.com/securityhub/home?region=${params.region}#/findings`;

  const message = `
ALERTA DE SEGURIDAD AWS - RESPUESTA AUTOMÁTICA ACTIVADA
=========================================================

DETALLES DEL HALLAZGO
----------------------
Tipo de Amenaza : ${params.findingType}
ID del Hallazgo : ${params.findingId}
Severidad       : ${params.severity} / 10 (${severityLabel})
Región          : ${params.region}
Cuenta AWS      : ${params.accountId}
Tipo de Recurso : ${params.resourceType}
Recurso         : ${params.resourceId}

ACCIÓN DE AISLAMIENTO EJECUTADA
---------------------------------
${params.isolationResult}

PRÓXIMOS PASOS RECOMENDADOS
-----------------------------
1. Revisar el hallazgo completo en AWS Security Hub
2. Verificar el aislamiento en la consola de AWS
3. Investigar la causa raíz en AWS CloudTrail
4. Coordinar con el equipo de seguridad para remediación
5. Documentar el incidente y las acciones tomadas
6. Una vez resuelto, levantar el aislamiento MANUALMENTE

Ver hallazgo en Security Hub:
${consoleUrl}

---------------------------------------------------------
Timestamp    : ${new Date().toISOString()}
Generado por : incident-response-isolate-resource (Lambda)
Región       : ${REGION}
  `.trim();

  await snsClient.send(
    new PublishCommand({
      TopicArn: SNS_TOPIC_ARN,
      Subject: `[SEGURIDAD ${severityLabel}] ${params.findingType} | ${params.region} | Acción automática ejecutada`,
      Message: message,
    })
  );

  console.log('[SNS] Alerta publicada exitosamente en el topic de seguridad');
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilidades
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Convierte el valor numérico de severidad de GuardDuty a una etiqueta legible.
 * Escala: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html
 */
function getSeverityLabel(severity: number): string {
  if (severity >= 9.0) return 'CRITICO';
  if (severity >= 7.0) return 'ALTO';
  if (severity >= 4.0) return 'MEDIO';
  return 'BAJO';
}
