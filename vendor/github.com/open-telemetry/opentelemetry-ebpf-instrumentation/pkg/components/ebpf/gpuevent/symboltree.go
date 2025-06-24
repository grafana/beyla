package gpuevent

// Interval represents an interval with a low and high value
type Symbol struct {
	Low, High uint64
	Symbol    string
}

// Node represents a node in the interval tree
type Node struct {
	Symbol Symbol
	Max    uint64
	Left   *Node
	Right  *Node
}

// SymbolTree represents the interval tree
type SymbolTree struct {
	Root *Node
}

// NewSymbolTree creates a new interval tree
func NewSymbolTree() *SymbolTree {
	return &SymbolTree{}
}

// Insert inserts a new interval into the interval tree
func (t *SymbolTree) Insert(sym Symbol) {
	t.Root = insert(t.Root, sym)
}

func insert(root *Node, sym Symbol) *Node {
	if root == nil {
		return &Node{
			Symbol: sym,
			Max:    sym.High,
		}
	}

	if sym.Low < root.Symbol.Low {
		root.Left = insert(root.Left, sym)
	} else {
		root.Right = insert(root.Right, sym)
	}

	if root.Max < sym.High {
		root.Max = sym.High
	}

	return root
}

// Search searches for intervals that overlap with the given point
func (t *SymbolTree) Search(point uint64) []Symbol {
	var result []Symbol
	search(t.Root, point, &result)
	return result
}

func search(root *Node, point uint64, result *[]Symbol) {
	if root == nil {
		return
	}

	if root.Symbol.Low <= point && point < root.Symbol.High {
		*result = append(*result, root.Symbol)
	}

	if root.Left != nil && root.Left.Max >= point {
		search(root.Left, point, result)
	}

	search(root.Right, point, result)
}
