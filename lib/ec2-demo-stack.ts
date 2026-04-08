import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

/**
 * Stack de EC2 para el demo en vivo.
 *
 * Crea una instancia t3.micro "víctima" en el VPC por defecto de la cuenta.
 * El simulate.sh la usa como blanco real del aislamiento automático,
 * permitiendo demostrar en vivo cómo el Security Group es reemplazado
 * por el SG de cuarentena (sin reglas de ingreso ni egreso).
 *
 * La instancia tiene acceso SSM para poder conectarse sin key pair
 * y verificar el aislamiento de red desde adentro si se desea.
 */
export class EC2DemoStack extends cdk.Stack {
  /** ID de la instancia exportado para uso en simulate.sh */
  public readonly instanceId: string;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Usar el VPC por defecto de la cuenta (existe en toda cuenta AWS nueva)
    // Si fue eliminado, crear uno con: aws ec2 create-default-vpc
    const vpc = ec2.Vpc.fromLookup(this, 'DefaultVpc', { isDefault: true });

    // Security Group inicial con reglas normales (lo que tendrá ANTES del ataque)
    const demoSG = new ec2.SecurityGroup(this, 'DemoInstanceSG', {
      vpc,
      description: 'SG inicial de la instancia demo - sera reemplazado al aislarla',
      allowAllOutbound: true,
    });

    // Permitir HTTPS saliente (simula una instancia con tráfico normal)
    demoSG.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'HTTPS entrante simulado'
    );

    // Role con SSM para poder conectarse sin key pair y verificar el aislamiento
    const instanceRole = new iam.Role(this, 'DemoInstanceRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'AmazonSSMManagedInstanceCore'
        ),
      ],
    });

    // Instancia "víctima" del demo
    const instance = new ec2.Instance(this, 'DemoInstance', {
      vpc,
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.T3,
        ec2.InstanceSize.MICRO
      ),
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
      securityGroup: demoSG,
      role: instanceRole,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      instanceName: 'demo-victim-instance',
    });

    this.instanceId = instance.instanceId;

    // Exportar el Instance ID — simulate.sh lo lee automáticamente
    new cdk.CfnOutput(this, 'DemoInstanceId', {
      value: instance.instanceId,
      description: 'ID de la instancia EC2 víctima para el demo de aislamiento',
      exportName: 'DemoEC2InstanceId',
    });

    new cdk.CfnOutput(this, 'DemoInstanceSGId', {
      value: demoSG.securityGroupId,
      description: 'SG original de la instancia (antes del aislamiento)',
      exportName: 'DemoEC2OriginalSGId',
    });
  }
}
