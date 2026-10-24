# CenaSync — dublagem colaborativa

Aplicação web para organizar cenas, editar um roteiro temporizado, gravar tomadas de voz, convidar amigos para salas de dublagem e revisar/exportar o resultado.

## O que está incluído

- React + TypeScript + Vite, com interface responsiva em português e tema cinematográfico escuro.
- API em Node.js + Express.
- Cadastro/login, nome de usuário único, avatar de emoji e ativação do modo Editor no servidor.
- SQLite para perfis, cenas, personagens, falas, amizades, salas, tomadas, feedbacks, notificações e tarefas de exportação.
- Armazenamento local persistente dos arquivos enviados em `server/storage/uploads`.
- Biblioteca, editor de cena, personagens e falas com timestamps, recorte de entrada/saída, salvamento automático com debounce, salvamento manual, publicação, histórico de versões da cena (com recuperação de estado no editor) e histórico de tomadas.
- Salas com código de convite, seleção de personagem e estado de prontidão.
- Gravação de áudio pelo navegador com seleção de microfone, medidor de entrada, contagem regressiva, prévia antes do envio e possibilidade de regravar.
- Pedidos de correção por fala e respostas do Editor.
- Revisão/aprovação de tomadas e exportação MP4 via FFmpeg, quando instalado e quando a cena usar vídeo enviado localmente.
- Integrações por player incorporado para YouTube/Instagram, respeitando as limitações de cada plataforma.

## Requisitos

- Node.js 22 ou superior (LTS recomendado) e npm. A dependência `better-sqlite3` foi atualizada para a série 13 para oferecer binários pré-compilados para versões modernas do Node, incluindo Node 24; Multer também está na série 2.x.
- FFmpeg instalado e disponível no `PATH` para exportar a composição final em MP4.
- Um navegador moderno. A gravação de microfone exige permissão do usuário e, em implantação pública, HTTPS.

## Executar em desenvolvimento (Windows)

Extraia o projeto em uma pasta local fora do OneDrive, por exemplo `C:\Dev\cenasync`, para evitar que a sincronização bloqueie arquivos em `node_modules`. Abra no VS Code exatamente a pasta que contém o `package.json` principal.

No PowerShell, confira se está na raiz do projeto:

```powershell
Test-Path .\package.json
```

O resultado deve ser `True`. Pare processos Node antigos antes de uma reinstalação. Se uma instalação anterior falhou, remova `node_modules` e `package-lock.json` da raiz do projeto (não remova arquivos `.env` ou o banco de dados) e reinstale:

```powershell
npm install
```

O `better-sqlite3` utiliza binários nativos. Para Node 24, utilize a versão atualizada declarada em `server/package.json`, em vez de reinstalar a versão antiga 11.x que não tinha o binário pré-compilado correspondente.

Copie `server/.env.example` para `server/.env` e altere, no mínimo, `JWT_SECRET` para um segredo longo e aleatório antes de publicar o site. Para desenvolvimento local, os valores exemplificados funcionam como configuração inicial.

Depois execute:

```bash
npm run dev
```

- Site: http://localhost:5173
- API: http://localhost:4000/api/health

O frontend usa `http://localhost:4000` como API automaticamente quando é servido pelo Vite na porta 5173. Para separar os serviços, defina `VITE_API_URL` no ambiente do cliente, conforme `client/.env.example`.

## Primeiro acesso e modo Editor

1. Crie uma conta com e-mail, senha, nome de usuário e avatar.
2. Para ativar o modo Editor, use o seletor de modo na parte superior e informe a chave configurada em `EDITOR_ACCESS_KEY` no arquivo `server/.env`.
3. O valor inicial solicitado para este projeto está preenchido no arquivo de exemplo. Troque-o antes de colocar a aplicação publicamente no ar.

A chave de ativação é verificada no servidor. Não a exponha no frontend ou em variáveis públicas `VITE_*`.

## Banco e arquivos

O banco SQLite é criado automaticamente em `server/storage/cenasync.sqlite`. Os arquivos enviados são armazenados em `server/storage/uploads`. Faça backups de ambos os locais. Não comite banco de produção, arquivos privados nem o arquivo `.env`.

A estrutura está preparada para desenvolvimento e implantação de baixo volume. Para múltiplos servidores ou grande número de usuários, use PostgreSQL e armazenamento de objetos compatível com S3, com jobs de processamento de mídia fora do processo HTTP.

## Build e produção

```bash
npm run build
npm start
```

O build do Vite é gerado em `client/dist`; o servidor Express serve essa pasta quando ela existe. Configure o proxy/reverse proxy e `CLIENT_ORIGIN` conforme o domínio real, use HTTPS e configure segredos de produção.

## Limitações importantes

- YouTube e Instagram são suportados por meio de player/link incorporado quando disponível. O site não baixa conteúdo de terceiros nem contorna restrições. A edição precisa de precisão de timestamps e a exportação MP4 dependem de um arquivo de vídeo enviado e autorizado.
- Se diálogo, música e efeitos vierem misturados na mesma faixa original, silenciar o áudio original também silencia música/efeitos. Separação de fontes não está embutida automaticamente.
- A exportação MP4 utiliza FFmpeg instalado no servidor e somente funciona com o vídeo local disponível e codecs suportados.
- A sincronização entre navegadores é coordenada na aplicação, mas não há garantia de sincronização de amostras perfeita entre dispositivos e redes diferentes.
- Não foi possível instalar dependências ou executar o build completo no ambiente de geração porque o acesso ao registro npm falhou por erro de rede (`EAI_AGAIN`). A estrutura foi verificada estaticamente, mas deve ser instalada e testada no ambiente de execução antes de publicar.

## Scripts

- `npm run dev`: inicia API e Vite em paralelo.
- `npm run dev:server`: inicia somente a API.
- `npm run dev:client`: inicia somente o frontend.
- `npm run build`: compila o frontend.
- `npm start`: inicia a API, que também serve o frontend compilado em produção.
