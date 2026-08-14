// Bun 以外のランタイム(npm 配布物を Node.js で起動した場合)を入口で止める
// 副作用モジュール。bin.ts の import 先頭に置くことで、他モジュールの評価より
// 先に必ず実行される(ES import はホイストされるため、bin.ts 本文にこの検査を
// 書いても「import 時に Bun API へ触れる変更」からは守れない)。
//
// 通しても keychain(Bun.secrets)や run(Bun.spawn)に触れた時点の
// ReferenceError になり、「ランタイム違い」という原因が利用者に伝わらない。

if (typeof globalThis.Bun === "undefined") {
  console.error(
    "maruhi CLI は Bun ランタイム上でのみ動作します(https://bun.sh)。" +
      "Bun を導入するか、GitHub Releases のコンパイル済みバイナリを利用してください。",
  );
  process.exit(1);
}
