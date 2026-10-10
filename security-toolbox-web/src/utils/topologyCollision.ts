export interface TopologyCollisionNode {
  id: string | number;
  x: number;
  y: number;
}

export interface TopologyCollisionDimensions {
  cardWidth: number;
  cardHeight: number;
  hubWidth: number;
  hubHeight: number;
  paddingX?: number;
  paddingY?: number;
  hubPaddingX?: number;
  hubPaddingY?: number;
}

interface Body {
  x: number;
  y: number;
  index: number;
  hub: boolean;
  fixed: boolean;
}

// Bodies are indexed by their centres. Cell dimensions cover the largest
// collision distance, so only the surrounding nine cells can intersect.
class SpatialBuckets {
  private readonly cells = new Map<string, Set<Body>>();

  constructor(private readonly width: number, private readonly height: number) {}

  private key(x: number, y: number): string {
    return `${Math.floor(x / this.width)},${Math.floor(y / this.height)}`;
  }

  add(body: Body): void {
    const key = this.key(body.x, body.y);
    let cell = this.cells.get(key);
    if (!cell) this.cells.set(key, (cell = new Set()));
    cell.add(body);
  }

  move(body: Body, x: number, y: number): void {
    const oldKey = this.key(body.x, body.y);
    const newKey = this.key(x, y);
    body.x = x;
    body.y = y;
    if (oldKey === newKey) return;
    const oldCell = this.cells.get(oldKey);
    oldCell?.delete(body);
    if (oldCell?.size === 0) this.cells.delete(oldKey);
    this.add(body);
  }

  near(x: number, y: number): Body[] {
    const column = Math.floor(x / this.width);
    const row = Math.floor(y / this.height);
    const result: Body[] = [];
    for (let dx = -1; dx <= 1; dx++) {
      for (let dy = -1; dy <= 1; dy++) {
        const cell = this.cells.get(`${column + dx},${row + dy}`);
        if (cell) for (const body of cell) result.push(body);
      }
    }
    return result;
  }
}

/**
 * Resolve automatic node positions without mutating inputs. Custom positions
 * and hubs stay fixed, including any overlaps the user explicitly created.
 * Sparse layouts inspect nearby buckets instead of every pair of nodes.
 */
export function resolveTopologyCollisions<T extends TopologyCollisionNode>(
  nodes: readonly T[],
  hubs: readonly { x: number; y: number }[],
  customMap: Readonly<Record<string | number, { x: number; y: number }>>,
  dimensions: TopologyCollisionDimensions,
): T[] {
  const nodeDistanceX = dimensions.cardWidth + (dimensions.paddingX ?? 26);
  const nodeDistanceY = dimensions.cardHeight + (dimensions.paddingY ?? 18);
  const hubDistanceX = (dimensions.hubWidth + dimensions.cardWidth) / 2
    + (dimensions.hubPaddingX ?? 32);
  const hubDistanceY = (dimensions.hubHeight + dimensions.cardHeight) / 2
    + (dimensions.hubPaddingY ?? 24);
  const cellWidth = Math.max(nodeDistanceX, hubDistanceX);
  const cellHeight = Math.max(nodeDistanceY, hubDistanceY);
  const epsilon = 1e-7;
  const result = nodes.map((node) => ({ ...node }));
  const bodies: Body[] = nodes.map((node, index) => ({
    x: node.x, y: node.y, index, hub: false, fixed: customMap[node.id] != null,
  }));
  const hubBodies: Body[] = hubs.map((hub, index) => ({
    x: hub.x, y: hub.y, index, hub: true, fixed: true,
  }));
  const buckets = new SpatialBuckets(cellWidth, cellHeight);
  for (const body of [...bodies, ...hubBodies]) buckets.add(body);

  // Retain the existing minimum-axis relaxation, but update the spatial index
  // immediately whenever a node crosses a cell boundary.
  for (let iteration = 0; iteration < 24; iteration++) {
    let moved = false;
    for (const a of bodies) {
      if (!a.fixed) {
        for (const hub of buckets.near(a.x, a.y)) {
          if (!hub.hub) continue;
          const dx = a.x - hub.x;
          const dy = a.y - hub.y;
          const overlapX = hubDistanceX - Math.abs(dx);
          const overlapY = hubDistanceY - Math.abs(dy);
          if (overlapX <= 0 || overlapY <= 0) continue;
          moved = true;
          if (overlapX < overlapY) {
            buckets.move(a, a.x + (dx >= 0 ? 1 : -1) * (overlapX + epsilon), a.y);
          } else {
            buckets.move(a, a.x, a.y + (dy >= 0 ? 1 : -1) * (overlapY + epsilon));
          }
        }
      }
      for (const b of buckets.near(a.x, a.y)) {
        if (b.hub || b.index <= a.index || (a.fixed && b.fixed)) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const overlapX = nodeDistanceX - Math.abs(dx);
        const overlapY = nodeDistanceY - Math.abs(dy);
        if (overlapX <= 0 || overlapY <= 0) continue;
        moved = true;
        const horizontal = overlapX < overlapY;
        const overlap = horizontal ? overlapX : overlapY;
        const sign = (horizontal ? dx : dy) >= 0 ? 1 : -1;
        const push = !a.fixed && !b.fixed ? overlap * 0.52 : overlap + epsilon;
        if (!a.fixed) {
          buckets.move(a, a.x - (horizontal ? sign * push : 0), a.y - (horizontal ? 0 : sign * push));
        }
        if (!b.fixed) {
          buckets.move(b, b.x + (horizontal ? sign * push : 0), b.y + (horizontal ? 0 : sign * push));
        }
      }
    }
    if (!moved) break;
  }

  // Bounded relaxation can leave small overlaps in dense groups. Place each
  // automatic node against fixed obstacles and already settled nodes. Each
  // directional search moves monotonically past an obstacle, so it terminates
  // without a global all-pairs fallback or displacing custom coordinates.
  const settled = new SpatialBuckets(cellWidth, cellHeight);
  for (const body of [...hubBodies, ...bodies.filter((body) => body.fixed)]) settled.add(body);
  const overlapsAt = (x: number, y: number) => settled.near(x, y).filter((other) =>
    Math.abs(x - other.x) < (other.hub ? hubDistanceX : nodeDistanceX)
    && Math.abs(y - other.y) < (other.hub ? hubDistanceY : nodeDistanceY));

  for (const body of bodies) {
    if (body.fixed) continue;
    if (overlapsAt(body.x, body.y).length > 0) {
      let bestX = body.x;
      let bestY = body.y;
      let bestDistance = Infinity;
      for (const [axis, sign] of [["x", 1], ["x", -1], ["y", 1], ["y", -1]] as const) {
        let x = body.x;
        let y = body.y;
        for (;;) {
          const collisions = overlapsAt(x, y);
          if (!collisions.length) break;
          let next = axis === "x" ? x : y;
          for (const other of collisions) {
            const distance = axis === "x"
              ? (other.hub ? hubDistanceX : nodeDistanceX)
              : (other.hub ? hubDistanceY : nodeDistanceY);
            const boundary = other[axis] + sign * (distance + epsilon);
            next = sign > 0 ? Math.max(next, boundary) : Math.min(next, boundary);
          }
          if (axis === "x") x = next;
          else y = next;
          // A farther candidate cannot improve the best clear position.
          if (Math.abs(x - body.x) + Math.abs(y - body.y) >= bestDistance) break;
        }
        const distance = Math.abs(x - body.x) + Math.abs(y - body.y);
        if (distance < bestDistance) {
          bestX = x;
          bestY = y;
          bestDistance = distance;
        }
      }
      body.x = bestX;
      body.y = bestY;
    }
    settled.add(body);
  }

  for (const body of bodies) {
    result[body.index]!.x = body.x;
    result[body.index]!.y = body.y;
  }
  return result;
}
