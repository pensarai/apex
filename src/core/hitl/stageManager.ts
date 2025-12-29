import { EventEmitter } from "events";
import type {
  HITLStage,
  StageProgress,
  HITLEvent,
} from "./types";
import { HITL_STAGES, getStagesInOrder, getNextStage } from "./types";

/**
 * StageManager tracks progress through the HITL workflow stages
 */
export class StageManager extends EventEmitter {
  private currentStage: HITLStage;
  private stageProgress: Record<HITLStage, StageProgress>;

  constructor(initialStage: HITLStage = "setup") {
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
  private createInitialProgress(): Record<HITLStage, StageProgress> {
    const progress = {} as Record<HITLStage, StageProgress>;
    for (const stage of Object.keys(HITL_STAGES) as HITLStage[]) {
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
  getCurrentStage(): HITLStage {
    return this.currentStage;
  }

  /**
   * Get current stage definition
   */
  getCurrentStageDefinition() {
    return HITL_STAGES[this.currentStage];
  }

  /**
   * Get progress for all stages
   */
  getProgress(): Record<HITLStage, StageProgress> {
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
  transitionTo(stage: HITLStage): void {
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
  advanceToNextStage(): HITLStage | null {
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
  isStageStarted(stage: HITLStage): boolean {
    return this.stageProgress[stage].started;
  }

  /**
   * Check if a stage is completed
   */
  isStageCompleted(stage: HITLStage): boolean {
    return this.stageProgress[stage].completed;
  }

  /**
   * Get suggested actions for current stage
   */
  getSuggestedActions(): string[] {
    return HITL_STAGES[this.currentStage].suggestedActions;
  }

  /**
   * Get stages summary for display
   */
  getStagesSummary(): Array<{
    stage: HITLStage;
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
   * Emit a typed HITL event
   */
  private emitEvent(event: HITLEvent): void {
    this.emit(event.type, event);
    this.emit("hitl-event", event);
  }

  /**
   * Serialize state for persistence
   */
  toJSON(): { currentStage: HITLStage; stageProgress: Record<HITLStage, StageProgress> } {
    return {
      currentStage: this.currentStage,
      stageProgress: this.stageProgress,
    };
  }

  /**
   * Restore state from serialized data
   */
  static fromJSON(data: {
    currentStage: HITLStage;
    stageProgress: Record<HITLStage, StageProgress>;
  }): StageManager {
    const manager = new StageManager(data.currentStage);
    manager.stageProgress = data.stageProgress;
    return manager;
  }
}
