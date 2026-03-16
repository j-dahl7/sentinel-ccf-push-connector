// CCF Push Connector Lab - Monitoring Module
// Log Analytics workspace + Microsoft Sentinel onboarding

@description('Azure region')
param location string

@description('Project name for resource naming')
param projectName string

var workspaceName = '${projectName}-law'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
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
}

output workspaceName string = workspace.name
output workspaceId string = workspace.id
output workspaceResourceId string = workspace.id
output workspaceCustomerId string = workspace.properties.customerId
