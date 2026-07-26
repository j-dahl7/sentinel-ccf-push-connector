// CCF Push Connector Lab - Main Bicep Template
// Deploys Log Analytics workspace + Microsoft Sentinel onboarding

targetScope = 'resourceGroup'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Project name used for resource naming')
param projectName string = 'ccf-push-lab'

@description('Unique local ownership token used to prevent resource adoption')
@minLength(36)
@maxLength(36)
param ownerToken string

module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring-${uniqueString(resourceGroup().id)}'
  params: {
    location: location
    projectName: projectName
    ownerToken: ownerToken
  }
}

output workspaceName string = monitoring.outputs.workspaceName
output workspaceId string = monitoring.outputs.workspaceId
output workspaceResourceId string = monitoring.outputs.workspaceResourceId
output workspaceCustomerId string = monitoring.outputs.workspaceCustomerId
