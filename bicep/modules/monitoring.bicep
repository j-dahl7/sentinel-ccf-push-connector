// CCF Push Connector Lab - Monitoring Module
// Log Analytics workspace + Microsoft Sentinel onboarding

@description('Azure region')
param location string

@description('Project name for resource naming')
param projectName string

@description('Unique local ownership token used to prevent resource adoption')
param ownerToken string

var workspaceName = '${projectName}-law'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: {
    'nlzt-owner': ownerToken
    'nlzt-lab': 'sentinel-ccf-push'
  }
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource sentinel 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'SecurityInsights(${workspaceName})'
  location: location
  plan: {
    name: 'SecurityInsights(${workspaceName})'
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
  }
  properties: {
    workspaceResourceId: workspace.id
  }
  tags: {
    'nlzt-owner': ownerToken
    'nlzt-lab': 'sentinel-ccf-push'
  }
}

resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  scope: workspace
  name: 'default'
  properties: {
    customerManagedKey: false
  }
}

output workspaceName string = workspace.name
output workspaceId string = workspace.id
output workspaceResourceId string = workspace.id
output workspaceCustomerId string = workspace.properties.customerId
