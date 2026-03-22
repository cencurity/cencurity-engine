package policy

import (
	"cencurity-engine/internal/detect"
	"cencurity-engine/internal/rules"
)

// Decision is the selected enforcement result for a set of detections.
type Decision struct {
	Action Action
	RuleID string
	Reason string
}

// Engine converts detections into a final stream action.
type Engine struct {
	rules *rules.Manager
}

// NewEngine creates the MVP policy engine.
func NewEngine(manager *rules.Manager) *Engine {
	return &Engine{rules: manager}
}

// Decide returns the strongest action for the current detections.
func (e *Engine) Decide(detections []detect.Detection, context detect.ContentContext) Decision {
	decision := Decision{Action: ActionAllow, RuleID: "none", Reason: "no_match"}
	for _, detection := range detections {
		next := contextualAction(parseAction(resolveAction(e.rules.ActionFor(detection.RuleID), detection.Action)), detection.Category, context)
		if rank(next) > rank(decision.Action) {
			decision.Action = next
			decision.RuleID = detection.RuleID
			decision.Reason = detection.Category + ":" + detection.RuleID
		}
	}
	return decision
}

func resolveAction(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func contextualAction(action Action, category string, context detect.ContentContext) Action {
	if action == ActionBlock && category != "secret" && context == detect.ContentContextPlain {
		return ActionRedact
	}
	return action
}

func parseAction(value string) Action {
	switch value {
	case string(ActionBlock):
		return ActionBlock
	case string(ActionRedact):
		return ActionRedact
	default:
		return ActionAllow
	}
}

func rank(action Action) int {
	switch action {
	case ActionBlock:
		return 3
	case ActionRedact:
		return 2
	default:
		return 1
	}
}
