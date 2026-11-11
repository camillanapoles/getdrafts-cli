package drafto

import (
	"encoding/json"

	"github.com/nerveband/drafts-applescript-cli/core"
)

// ParseAction builds a core.Action from a compact JSON definition.
//
// Example:
//
//	{"group":"Quick","steps":[{"type":"copy"},{"type":"archive"}],"after_success":"archive"}
func ParseAction(name, defJSON string) (core.Action, error) {
	var def struct {
		Group        string `json:"group"`
		Steps        []struct {
			Type   string                 `json:"type"`
			Config map[string]interface{} `json:"config"`
		} `json:"steps"`
		AfterSuccess string `json:"after_success"`
	}
	if err := json.Unmarshal([]byte(defJSON), &def); err != nil {
		return core.Action{}, err
	}

	steps := make([]core.ActionStep, len(def.Steps))
	for i, s := range def.Steps {
		steps[i] = core.ActionStep{
			Type:   core.ActionStepType(s.Type),
			Config: s.Config,
		}
	}

	return core.Action{
		UUID:         name,
		Name:         name,
		Group:        def.Group,
		Steps:        steps,
		AfterSuccess: def.AfterSuccess,
	}, nil
}
