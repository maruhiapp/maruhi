// Shared parts of the load-time sweeps over the HttpApi definition
// (strict.ts / session-capability.ts).
//
// Both sweeps take the HttpApi via a structural type (the concrete
// `HttpApi<...>` is invariant in its group union, so the nominal
// `HttpApi.Top` cannot be a parameter type — see each file's
// `SweepableApi` comment). Only the traversal shape is shared here; the
// per-endpoint check stays with the caller.

/**
 * Existence check for one enumerated-list entry: requires the group
 * and endpoint to exist. `sweepLabel` is the error-message prefix of
 * each sweep.
 */
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

/** Traversal of every registered endpoint. `key` is `"group.endpoint"`. */
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
