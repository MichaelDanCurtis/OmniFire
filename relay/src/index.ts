export { MeshDurableObject } from './mesh_do';

interface Env {
  MESH: DurableObjectNamespace;
}

const MESH_PATH = /^\/v1\/mesh\/([^/]+)\/ws$/;
const HEX_MESH_ID = /^[0-9a-f]{32}$/;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/v1/health') {
      return Response.json({ ok: true });
    }

    const match = MESH_PATH.exec(url.pathname);
    if (!match) {
      return new Response('not found', { status: 404 });
    }

    const meshId = match[1];
    if (!HEX_MESH_ID.test(meshId)) {
      return new Response('bad mesh id', { status: 400 });
    }

    const id = env.MESH.idFromName(meshId);
    return env.MESH.get(id).fetch(request);
  },
};
