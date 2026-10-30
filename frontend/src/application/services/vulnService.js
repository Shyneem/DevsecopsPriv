import apiClient from '../../infrastructure/http/apiClient';

export default {
  getVulns: async (params = {}) => {
    const queryParams = {}

    if (params.page !== undefined && params.page !== null && params.page !== '') {
      queryParams.page = params.page
    }

    const pageSize = params.pageSize !== undefined ? params.pageSize : params.page_size
    if (pageSize !== undefined && pageSize !== null && pageSize !== '') {
      queryParams.page_size = pageSize
    }

    const connectionId = params.connectionId !== undefined ? params.connectionId : params.connection_id
    if (connectionId !== undefined && connectionId !== null && connectionId !== '') {
      queryParams.connection_id = connectionId
    }

    if (params.severity) {
      queryParams.severity = params.severity
    }

    if (params.status) {
      queryParams.status = params.status
    }

    const agentId = params.agentId !== undefined ? params.agentId : params.agent_id
    if (agentId) {
      queryParams.agent_id = agentId
    }

    const agentName = params.agentName !== undefined ? params.agentName : params.agent_name
    if (agentName) {
      queryParams.agent_name = agentName
    }

    const cveId = params.cveId !== undefined ? params.cveId : params.cve_id
    if (cveId) {
      queryParams.cve_id = cveId
    }

    const packageName = params.packageName !== undefined ? params.packageName : params.package_name
    if (packageName) {
      queryParams.package_name = packageName
    }

    if (params.search) {
      queryParams.search = params.search
    }

    const sortBy = params.sortBy !== undefined ? params.sortBy : params.sort_by
    if (sortBy) {
      queryParams.sort_by = sortBy
    }

    const sortOrder = params.sortOrder !== undefined ? params.sortOrder : params.sort_order
    if (sortOrder) {
      queryParams.sort_order = sortOrder
    }

    if (params.limit !== undefined && params.limit !== null && params.limit !== '') {
      queryParams.limit = params.limit
    }

    return apiClient.get('/vulns', {
      params: queryParams,
    })
  },

  syncVulns: async () => {
    return apiClient.post('/vulns/sync-all')
  },
}
