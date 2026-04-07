/**
 * Configuración central del proyecto aws-incident-response
 *
 * Demo: "Nadie Apretó un Botón: Respuesta Automática a Incidentes con AWS Nativo"
 *
 * Modifica estos valores ANTES de ejecutar `cdk deploy`.
 * Consulta el README.md para instrucciones detalladas.
 */
export declare const config: {
    /**
     * Email que recibirá las alertas de seguridad vía SNS.
     * ⚠️  IMPORTANTE: Cambia esto por tu email antes de desplegar.
     *                 Recibirás un email de confirmación de AWS.
     */
    alertEmail: string;
    /**
     * Región de AWS donde se despliega la solución completa.
     * GuardDuty, Security Hub y todos los recursos quedarán en esta región.
     */
    region: string;
    /**
     * Severidad mínima de GuardDuty para disparar el aislamiento automático.
     *
     * Escala de GuardDuty (1.0 - 10.0):
     *   LOW      → 1.0 - 3.9  (informativo, sin acción automática)
     *   MEDIUM   → 4.0 - 6.9  (investigar manualmente)
     *   HIGH     → 7.0 - 8.9  (respuesta automática recomendada)  ← umbral por defecto
     *   CRITICAL → 9.0 - 10.0 (respuesta inmediata requerida)
     *
     * Para el demo: usa 7 (HIGH) para demostrar con sample findings.
     */
    minSeverityToIsolate: number;
    /**
     * Feature flags para controlar qué protecciones habilitar en GuardDuty.
     * Desactiva las que no necesites para reducir costos en entornos de prueba.
     */
    featureFlags: {
        /** Protección de buckets S3 - monitorea accesos anómalos */
        enableS3Protection: boolean;
        /** Protección de workloads en Amazon EKS - audit logs de Kubernetes */
        enableEKSProtection: boolean;
        /** Protección contra malware en volúmenes EBS */
        enableMalwareProtection: boolean;
        /** Exportar frecuencia de hallazgos: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS */
        findingPublishingFrequency: "FIFTEEN_MINUTES" | "ONE_HOUR" | "SIX_HOURS";
    };
};
