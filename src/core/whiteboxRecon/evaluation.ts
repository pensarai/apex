import type { ReconSurface, WhiteboxReconResult } from "./types";

export interface WhiteboxReconGroundTruth {
  surfaces: ReconSurface[];
}

export interface WhiteboxReconEvaluation {
  expected: number;
  discovered: number;
  exact_matches: number;
  interface_recall: number;
  interface_precision: number;
  application_assignment_accuracy: number;
  source_file_accuracy: number;
  source_line_accuracy: number;
  unresolved: number;
  model_calls: number;
  input_tokens: number;
  output_tokens: number;
  duration_ms: number;
}

export function evaluateWhiteboxRecon(
  result: WhiteboxReconResult,
  groundTruth: WhiteboxReconGroundTruth,
): WhiteboxReconEvaluation {
  const expectedByOperation = new Map(
    groundTruth.surfaces.map((surface) => [
      operationIdentity(surface),
      surface,
    ]),
  );
  const actualByOperation = new Map(
    result.surfaces.map((surface) => [operationIdentity(surface), surface]),
  );
  const exactMatches = [...expectedByOperation.keys()].filter((identity) =>
    actualByOperation.has(identity),
  );
  const expectedByInterface = new Map(
    groundTruth.surfaces.map((surface) => [
      interfaceIdentity(surface),
      surface,
    ]),
  );
  const actualByInterface = new Map(
    result.surfaces.map((surface) => [interfaceIdentity(surface), surface]),
  );
  const interfaceMatches = [...expectedByInterface.keys()].flatMap(
    (identity) => {
      const expected = expectedByInterface.get(identity);
      const actual = actualByInterface.get(identity);
      return expected && actual ? [{ expected, actual }] : [];
    },
  );
  const sourceFileMatches = interfaceMatches.filter(
    ({ expected, actual }) => expected.source_file === actual.source_file,
  );

  return {
    expected: expectedByOperation.size,
    discovered: actualByOperation.size,
    exact_matches: exactMatches.length,
    interface_recall: ratio(interfaceMatches.length, expectedByInterface.size),
    interface_precision: ratio(interfaceMatches.length, actualByInterface.size),
    application_assignment_accuracy: ratio(
      interfaceMatches.filter(
        ({ expected, actual }) =>
          expected.application_id === actual.application_id,
      ).length,
      interfaceMatches.length,
    ),
    source_file_accuracy: ratio(
      sourceFileMatches.length,
      interfaceMatches.length,
    ),
    source_line_accuracy: ratio(
      sourceFileMatches.filter(
        ({ expected, actual }) => expected.source_line === actual.source_line,
      ).length,
      interfaceMatches.length,
    ),
    unresolved: result.unresolved.length,
    model_calls: result.metrics.agent_calls,
    input_tokens: result.metrics.tokens_in,
    output_tokens: result.metrics.tokens_out,
    duration_ms: result.metrics.duration_ms,
  };
}

function operationIdentity(surface: ReconSurface): string {
  return [
    surface.application_id,
    surface.type,
    surface.method?.toUpperCase() ?? "",
    surface.path_or_name,
  ].join("\u0000");
}

function interfaceIdentity(surface: ReconSurface): string {
  return [
    surface.type,
    surface.method?.toUpperCase() ?? "",
    surface.path_or_name,
  ].join("\u0000");
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 1 : numerator / denominator;
}
