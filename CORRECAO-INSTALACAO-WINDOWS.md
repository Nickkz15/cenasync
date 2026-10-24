# Correção do erro `better-sqlite3` no Windows / Node 24

O log mostra que o npm resolveu `better-sqlite3` para a versão 11.10.0. Essa versão não disponibiliza o binário pré-compilado para Node 24, então o npm tentou compilar C++ localmente; a compilação falhou porque o Python do ambiente Windows não foi detectado corretamente.

O projeto foi atualizado para `better-sqlite3` 13.x, cuja série utiliza N-API e fornece binários pré-compilados para versões modernas do Node, e para Multer 2.x para evitar a dependência antiga que gerava o aviso de segurança.

## Passos

1. Feche terminais em que `npm run dev` esteja ativo.
2. Recomenda-se mover/copiar o projeto para fora do OneDrive, por exemplo `C:\Dev\cenasync`. Os avisos `EBUSY` e `EPERM` no log indicam diretórios bloqueados durante a limpeza.
3. Abra a pasta que contém o `package.json` principal.
4. No PowerShell execute:

```powershell
Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -Recurse -Force .\node_modules -ErrorAction SilentlyContinue
Remove-Item -Force .\package-lock.json -ErrorAction SilentlyContinue
Test-Path .\package.json
npm install
```

O `Test-Path` deve retornar `True`. Execute os comandos a partir da raiz do CenaSync, não de `client` nem de `server`.

Depois, confira o build e inicie a aplicação:

```powershell
npm run build
Copy-Item .\server\.env.example .\server\.env -ErrorAction SilentlyContinue
npm run dev
```

Se o npm ainda tentar compilar `better-sqlite3` e falhar, confira que `server/package.json` contém `"better-sqlite3": "^13.0.3"` e que o `npm install` foi executado na raiz do projeto.
