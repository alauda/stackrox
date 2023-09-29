// Copyright 2023 Undistro Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package celcompile

import (
	"fmt"

	mito "github.com/elastic/mito/lib"
	"github.com/google/cel-go/cel"
)

var celEnvOptions = []cel.EnvOption{
	cel.EagerlyValidateDeclarations(true),
	cel.DefaultUTCTimeZone(true),
	// ext.Strings(ext.StringsVersion(2)),
	// cel.CrossTypeNumericComparisons(true),
	// cel.OptionalTypes(),
	// k8s.URLs(),
	// k8s.Regex(),
	// k8s.Lists(),
	// k8s.Quantity(),
	mito.Collections(),
}

var celProgramOptions = []cel.ProgramOption{
	cel.EvalOptions(cel.OptOptimize),
	// cel.EvalOptions(cel.OptOptimize, cel.OptTrackCost),
}

// eval evaluates the cel expression against the given input
func compile(exp string) (cel.Program, error) {
	inputVars := make([]cel.EnvOption, 0, 1)
	inputVars = append(inputVars, cel.Variable("obj", cel.DynType))
	env, err := cel.NewEnv(append(celEnvOptions, inputVars...)...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL env: %w", err)
	}
	ast, issues := env.Compile(exp)
	if issues != nil {
		return nil, fmt.Errorf("failed to compile the CEL expression: %s", issues.String())
	}
	prog, err := env.Program(ast, celProgramOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate CEL program: %w", err)
	}
	return prog, nil
}
