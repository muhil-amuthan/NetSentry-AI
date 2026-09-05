"""
Network topology handling.

Loads ``data/topology.json`` into the models defined in :mod:`src.models` and
exposes read-only graph queries over it: neighbour lookup, path finding,
reachability from the network edge, and downstream fan-out.

Scope note (Step 3)
-------------------
Everything here is *structural*. These queries answer "how is the network wired
and what sits behind this device", which is a property of the graph itself.
They deliberately do **not** answer "which alerts belong together", "how bad is
this" or "what should the operator do" — correlation, deduplication, scoring,
priority, runbook retrieval and the LLM layer are separate later steps that
will call into this module for topology context.

Typical use::

    from src.topology import get_topology

    topo = get_topology()
    topo.neighbors("R1")            # ['INTERNET', 'R2', 'S1', 'S2']
    topo.downstream("R1")           # everything that hangs off R1
    topo.impact_of_failure("R1")    # nodes isolated if R1 dies
"""

from __future__ import annotations

import json
from collections import deque
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set

from src.config import TOPOLOGY_FILE
from src.models import Link, NetworkLayer, Node, Topology


class TopologyError(RuntimeError):
    """Raised when a topology document is missing, malformed or inconsistent."""


class NetworkTopology:
    """An in-memory, read-only view of the network graph.

    The graph is treated as undirected for connectivity purposes (a cable
    carries traffic both ways), while ``layer`` on each node provides the
    hierarchy needed for "upstream"/"downstream" questions.
    """

    #: Layers ordered from the network edge inwards.
    _LAYER_DEPTH: Dict[NetworkLayer, int] = {
        NetworkLayer.EXTERNAL: 0,
        NetworkLayer.CORE: 1,
        NetworkLayer.DISTRIBUTION: 2,
        NetworkLayer.ACCESS: 3,
    }

    def __init__(self, topology: Topology) -> None:
        self._topology = topology
        self._nodes: Dict[str, Node] = {n.id: n for n in topology.nodes}
        self._links: List[Link] = list(topology.links)

        self._validate()

        # Adjacency: node id -> set of directly connected node ids.
        self._adjacency: Dict[str, Set[str]] = {node_id: set() for node_id in self._nodes}
        # Link index: frozenset of endpoints -> Link, for O(1) edge lookup.
        self._link_index: Dict[frozenset, Link] = {}

        for link in self._links:
            self._adjacency[link.source].add(link.target)
            self._adjacency[link.target].add(link.source)
            self._link_index[frozenset((link.source, link.target))] = link

    # -- construction -------------------------------------------------------

    @classmethod
    def from_dict(cls, payload: dict) -> "NetworkTopology":
        """Build a topology from an already-parsed JSON document."""
        try:
            return cls(Topology.model_validate(payload))
        except Exception as exc:  # pydantic ValidationError and friends
            raise TopologyError(f"invalid topology document: {exc}") from exc

    @classmethod
    def from_file(cls, path: Optional[Path] = None) -> "NetworkTopology":
        """Load a topology from a JSON file (defaults to ``TOPOLOGY_FILE``)."""
        target = Path(path) if path else TOPOLOGY_FILE
        if not target.exists():
            raise TopologyError(f"topology file not found: {target}")
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise TopologyError(f"topology file is not valid JSON: {target}: {exc}") from exc
        return cls.from_dict(payload)

    def _validate(self) -> None:
        """Reject duplicate node ids and links that dangle off the graph."""
        seen: Set[str] = set()
        for node in self._topology.nodes:
            if node.id in seen:
                raise TopologyError(f"duplicate node id: {node.id}")
            seen.add(node.id)

        for link in self._links:
            for endpoint in link.endpoints():
                if endpoint not in self._nodes:
                    raise TopologyError(
                        f"link {link.id} references unknown node '{endpoint}'"
                    )
            if link.source == link.target:
                raise TopologyError(f"link {link.id} connects node '{link.source}' to itself")

    # -- basic accessors ----------------------------------------------------

    @property
    def name(self) -> str:
        return self._topology.name

    @property
    def region(self) -> Optional[str]:
        return self._topology.region

    @property
    def nodes(self) -> List[Node]:
        """All nodes, in document order."""
        return list(self._nodes.values())

    @property
    def links(self) -> List[Link]:
        """All links, in document order."""
        return list(self._links)

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: object) -> bool:
        return node_id in self._nodes

    def get_node(self, node_id: str) -> Optional[Node]:
        """Return a node by id, or ``None`` if it is not in the topology."""
        return self._nodes.get(node_id)

    def require_node(self, node_id: str) -> Node:
        """Return a node by id, raising :class:`TopologyError` if unknown."""
        node = self._nodes.get(node_id)
        if node is None:
            raise TopologyError(f"unknown node: {node_id}")
        return node

    def get_link(self, a: str, b: str) -> Optional[Link]:
        """Return the link directly joining two nodes, if one exists."""
        return self._link_index.get(frozenset((a, b)))

    def links_for(self, node_id: str) -> List[Link]:
        """Every link with ``node_id`` as an endpoint."""
        return [link for link in self._links if node_id in link.endpoints()]

    def nodes_by_layer(self, layer: NetworkLayer) -> List[Node]:
        """All nodes sitting in a given network layer."""
        return [n for n in self._nodes.values() if n.layer == layer]

    def nodes_by_site(self, site: str) -> List[Node]:
        """All nodes at a given site/POP."""
        return [n for n in self._nodes.values() if n.site == site]

    # -- graph queries ------------------------------------------------------

    def neighbors(self, node_id: str) -> List[str]:
        """Ids of nodes directly connected to ``node_id`` (sorted, stable)."""
        self.require_node(node_id)
        return sorted(self._adjacency[node_id])

    def degree(self, node_id: str) -> int:
        """Number of links attached to a node."""
        return len(self.neighbors(node_id))

    def shortest_path(self, source: str, target: str) -> List[str]:
        """Breadth-first shortest path between two nodes.

        Returns the node ids from ``source`` to ``target`` inclusive, or an
        empty list when no path exists.
        """
        self.require_node(source)
        self.require_node(target)
        if source == target:
            return [source]

        previous: Dict[str, Optional[str]] = {source: None}
        queue: deque[str] = deque([source])

        while queue:
            current = queue.popleft()
            for neighbor in sorted(self._adjacency[current]):
                if neighbor in previous:
                    continue
                previous[neighbor] = current
                if neighbor == target:
                    return self._rebuild_path(previous, target)
                queue.append(neighbor)
        return []

    @staticmethod
    def _rebuild_path(previous: Dict[str, Optional[str]], target: str) -> List[str]:
        path: List[str] = []
        cursor: Optional[str] = target
        while cursor is not None:
            path.append(cursor)
            cursor = previous[cursor]
        path.reverse()
        return path

    def downstream(self, node_id: str) -> List[str]:
        """Nodes that sit *below* ``node_id`` in the hierarchy and reach it.

        A node is downstream when it is strictly deeper (access is deeper than
        distribution, which is deeper than core) and is reachable from
        ``node_id`` without passing back up through a shallower layer.
        """
        start = self.require_node(node_id)
        start_depth = self._depth(start)

        found: Set[str] = set()
        queue: deque[str] = deque([node_id])
        visited: Set[str] = {node_id}

        while queue:
            current = queue.popleft()
            for neighbor_id in sorted(self._adjacency[current]):
                if neighbor_id in visited:
                    continue
                neighbor = self._nodes[neighbor_id]
                if self._depth(neighbor) <= start_depth:
                    continue  # same layer or upstream: not downstream traffic
                visited.add(neighbor_id)
                found.add(neighbor_id)
                queue.append(neighbor_id)
        return sorted(found)

    def upstream(self, node_id: str) -> List[str]:
        """Direct neighbours that sit closer to the network edge."""
        node = self.require_node(node_id)
        depth = self._depth(node)
        return sorted(
            nid for nid in self._adjacency[node_id] if self._depth(self._nodes[nid]) < depth
        )

    def _depth(self, node: Node) -> int:
        return self._LAYER_DEPTH.get(node.layer, len(self._LAYER_DEPTH))

    # -- reachability -------------------------------------------------------

    def entry_points(self) -> List[str]:
        """Ids of the external/transit nodes traffic enters the network through."""
        return sorted(n.id for n in self._nodes.values() if n.layer == NetworkLayer.EXTERNAL)

    def reachable_from(
        self, sources: Iterable[str], excluded: Optional[Sequence[str]] = None
    ) -> Set[str]:
        """Set of nodes reachable from ``sources``, ignoring ``excluded`` nodes.

        Used to answer connectivity questions such as "what is still online if
        this device is removed from the graph".
        """
        blocked = set(excluded or ())
        seen: Set[str] = set()
        queue: deque[str] = deque()

        for source in sources:
            if source in self._nodes and source not in blocked:
                seen.add(source)
                queue.append(source)

        while queue:
            current = queue.popleft()
            for neighbor in self._adjacency[current]:
                if neighbor in seen or neighbor in blocked:
                    continue
                seen.add(neighbor)
                queue.append(neighbor)
        return seen

    def impact_of_failure(self, node_id: str) -> List[str]:
        """Nodes that lose their path to the network edge if ``node_id`` fails.

        Purely a connectivity calculation over the graph: it compares what is
        reachable from the entry points with and without the node. It assigns
        no severity, score or priority — that is the later engines' job.
        """
        self.require_node(node_id)
        entries = self.entry_points()
        if not entries:
            return []

        before = self.reachable_from(entries)
        after = self.reachable_from(entries, excluded=[node_id])
        return sorted((before - after) - {node_id})

    def affected_subscribers(self, node_ids: Iterable[str]) -> int:
        """Total subscribers served by the given nodes (each counted once)."""
        return sum(
            self._nodes[nid].subscribers for nid in set(node_ids) if nid in self._nodes
        )

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise back to a plain dict, ready to be returned by the API."""
        return self._topology.model_dump(mode="json")

    def summary(self) -> dict:
        """Small overview of the graph, handy for health and debug endpoints."""
        counts: Dict[str, int] = {}
        for node in self._nodes.values():
            counts[node.layer.value] = counts.get(node.layer.value, 0) + 1
        return {
            "name": self.name,
            "region": self.region,
            "node_count": len(self._nodes),
            "link_count": len(self._links),
            "nodes_by_layer": counts,
            "sites": sorted({n.site for n in self._nodes.values()}),
            "total_subscribers": sum(n.subscribers for n in self._nodes.values()),
        }

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<NetworkTopology {self.name!r} nodes={len(self._nodes)} links={len(self._links)}>"


@lru_cache(maxsize=1)
def get_topology() -> NetworkTopology:
    """Load and cache the default topology document.

    Cached because the file is read-only at runtime; call
    :func:`reload_topology` after editing ``topology.json``.
    """
    return NetworkTopology.from_file()


def reload_topology() -> NetworkTopology:
    """Clear the cache and re-read the topology from disk."""
    get_topology.cache_clear()
    return get_topology()


__all__ = [
    "NetworkTopology",
    "TopologyError",
    "get_topology",
    "reload_topology",
]
