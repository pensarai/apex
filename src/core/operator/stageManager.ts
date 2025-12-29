import { EventEmitter } from "events";
import type {
  OperatorStage,
  StageProgress,
  OperatorEvent,
} from "./types";
import { OPERATOR_STAGES, getStagesInOrder, getNextStage } from "./types";

/**
 * StageManager tracks progress through the Operator workflow stages
 */
export class StageManager extends EventEmitter {
  private currentStage: OperatorStage;
  private stageProgress: Record<OperatorStage, StageProgress>;

  constructor(initialStage: OperatorStage = "setup") {
    super();
    this.currentStage = initialStage;
    this.stageProgress = this.createInitialProgress();

    // Mark initial stage as started
    this.stageProgress[initialStage].started = true;
    this.stageProgress[initialStage].startedAt = Date.now();
  }

  /**
   * Create initial progress tracking for all stages
   */
  private createInitialProgress(): Record<OperatorStage, StageProgress> {
    const progress = {} as Record<OperatorStage, StageProgress>;
    for (const stage of Object.keys(OPERATOR_STAGES) as OperatorStage[]) {
      progress[stage] = {
        started: false,
        completed: false,
      };
    }
    return progress;
  }

  /**
   * Get current stage
   */
  getCurrentStage(): OperatorStage {
    return this.currentStage;
  }

  /**
   * Get current stage definition
   */
  getCurrentStageDefinition() {
    return OPERATOR_STAGES[this.currentStage];
  }

  /**
   * Get progress for all stages
   */
  getProgress(): Record<OperatorStage, StageProgress> {
    return { ...this.stageProgress };
  }

  /**
   * Get progress percentage (0-100)
   */
  getProgressPercentage(): number {
    const stages = getStagesInOrder();
    const currentIndex = stages.findIndex((s) => s.stage === this.currentStage);
    return Math.round(((currentIndex + 1) / stages.length) * 100);
  }

  /**
   * Transition to a new stage
   */
  transitionTo(stage: OperatorStage): void {
    if (stage === this.currentStage) {
      return;
    }

    // Mark current stage as completed
    this.stageProgress[this.currentStage].completed = true;
    this.stageProgress[this.currentStage].completedAt = Date.now();

    // Update current stage
    const previousStage = this.currentStage;
    this.currentStage = stage;

    // Mark new stage as started
    if (!this.stageProgress[stage].started) {
      this.stageProgress[stage].started = true;
      this.stageProgress[stage].startedAt = Date.now();
    }

    // Emit event
    this.emitEvent({ type: "stage-changed", stage });
  }

  /**
   * Advance to the next stage
   */
  advanceToNextStage(): OperatorStage | null {
    const nextStage = getNextStage(this.currentStage);
    if (nextStage) {
      this.transitionTo(nextStage);
    }
    return nextStage;
  }

  /**
   * Check if current stage is completed
   */
  isCurrentStageCompleted(): boolean {
    return this.stageProgress[this.currentStage].completed;
  }

  /**
   * Check if a stage has been started
   */
  isStageStarted(stage: OperatorStage): boolean {
    return this.stageProgress[stage].started;
  }

  /**
   * Check if a stage is completed
   */
  isStageCompleted(stage: OperatorStage): boolean {
    return this.stageProgress[stage].completed;
  }

  /**
   * Get suggested actions for current stage
   */
  getSuggestedActions(): string[] {
    return OPERATOR_STAGES[this.currentStage].suggestedActions;
  }

  /**
   * Get stages summary for display
   */
  getStagesSummary(): Array<{
    stage: OperatorStage;
    name: string;
    status: "pending" | "current" | "completed";
    order: number;
  }> {
    return getStagesInOrder().map((def) => ({
      stage: def.stage,
      name: def.name,
      order: def.order,
      status:
        this.stageProgress[def.stage].completed
          ? "completed"
          : def.stage === this.currentStage
          ? "current"
          : "pending",
    }));
  }

  /**
   * Emit a typed Operator event
   */
  private emitEvent(event: OperatorEvent): void {
    this.emit(event.type, event);
    this.emit("operator-event", event);
  }

  /**
   * Serialize state for persistence
   */
  toJSON(): { currentStage: OperatorStage; stageProgress: Record<OperatorStage, StageProgress> } {
    return {
      currentStage: this.currentStage,
      stageProgress: this.stageProgress,
    };
  }

  /**
   * Restore state from serialized data
   */
  static fromJSON(data: {
    currentStage: OperatorStage;
    stageProgress: Record<OperatorStage, StageProgress>;
  }): StageManager {
    const manager = new StageManager(data.currentStage);
    manager.stageProgress = data.stageProgress;
    return manager;
  }
}
