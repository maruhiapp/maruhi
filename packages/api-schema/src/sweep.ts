export function requireRegisteredEndpoint<Endpoint>(
  api: {
    readonly groups: {
      readonly [group: string]: { readonly endpoints: { readonly [endpoint: string]: Endpoint } };
    };
  },
  sweepLabel: string,
  groupName: string,
  endpointName: string,
): Endpoint {
  const group = api.groups[groupName];
  if (group === undefined) {
    throw new Error(`${sweepLabel}: unknown group "${groupName}"`);
  }
  const endpoint = group.endpoints[endpointName];
  if (endpoint === undefined) {
    throw new Error(`${sweepLabel}: unknown endpoint "${groupName}.${endpointName}"`);
  }
  return endpoint;
}

export function forEachEndpoint<Endpoint>(
  api: {
    readonly groups: {
      readonly [group: string]: { readonly endpoints: { readonly [endpoint: string]: Endpoint } };
    };
  },
  visit: (key: string, endpoint: Endpoint) => void,
): void {
  for (const [groupName, group] of Object.entries(api.groups)) {
    for (const [endpointName, endpoint] of Object.entries(group.endpoints)) {
      visit(`${groupName}.${endpointName}`, endpoint);
    }
  }
}
