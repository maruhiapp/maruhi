// HttpApi 定義のロード時スイープの共通部品(strict.ts / session-capability.ts)。
//
// 両スイープは構造型で HttpApi を受ける(具象 `HttpApi<...>` はグループ Union に
// 不変で、公称型 `HttpApi.Top` を引数型に使えない — 各ファイルの `SweepableApi`
// コメント参照)。ここで共有するのは走査の形のみで、エンドポイントごとの検査は
// 呼び出し側に置く。

/**
 * 列挙リスト 1 件の実在検査: グループ・エンドポイントの存在を要求する。
 * `sweepLabel` は各スイープのエラーメッセージ接頭辞。
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

/** 登録済み全エンドポイントの走査。`key` は `"group.endpoint"`。 */
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
