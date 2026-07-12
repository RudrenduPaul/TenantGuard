package collector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// lineIndex resolves a dotted path (mapping keys and numeric sequence
// indices, e.g. "tools.exec.0.approvals") against a parsed yaml.Node tree and
// returns the source line of a given item within the sequence found at that
// path. This is what lets a Finding cite "config/exec.yml:18" instead of just
// "config/exec.yml somewhere."
type lineIndexer struct {
	root *yaml.Node
}

func lineIndex(root *yaml.Node) lineIndexer {
	return lineIndexer{root: root}
}

// lookup returns the line number of Content[itemIndex] of the sequence node
// found by walking path from the document root. Returns 0 (unknown) if the
// path can't be resolved — a missing line number is a display nicety, never a
// reason to fail the scan.
func (li lineIndexer) lookup(path string, itemIndex int) int {
	if li.root == nil || len(li.root.Content) == 0 {
		return 0
	}
	node := li.root.Content[0] // document root's single top-level mapping node
	for _, part := range strings.Split(path, ".") {
		if idx, err := strconv.Atoi(part); err == nil {
			if node.Kind != yaml.SequenceNode || idx >= len(node.Content) {
				return 0
			}
			node = node.Content[idx]
			continue
		}
		node = mapValue(node, part)
		if node == nil {
			return 0
		}
	}
	if node.Kind != yaml.SequenceNode || itemIndex >= len(node.Content) {
		return 0
	}
	return node.Content[itemIndex].Line
}

// lookupScalar resolves a dotted path of mapping keys only (no sequence
// index) and returns the source line of the scalar value found there, plus
// whether the path was declared at all. This is what lets a deployment-level
// singleton field like sandbox.on_unavailable (TA09) distinguish "declared
// but wrong value" (cite a real line) from "never declared" (no line to
// cite, found is false).
func (li lineIndexer) lookupScalar(path string) (line int, found bool) {
	if li.root == nil || len(li.root.Content) == 0 {
		return 0, false
	}
	node := li.root.Content[0]
	for _, part := range strings.Split(path, ".") {
		node = mapValue(node, part)
		if node == nil {
			return 0, false
		}
	}
	return node.Line, true
}

// mapValue returns the value node for key in a yaml mapping node, or nil if
// node isn't a mapping or the key isn't present.
func mapValue(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
