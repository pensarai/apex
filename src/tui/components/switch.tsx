import React, { type ReactElement, type ReactNode } from 'react';

// Define types for props
export interface CaseProps<T extends string> {
  when: T;
  children: ReactNode;
}

export interface DefaultProps {
  children: ReactNode;
}

export interface SwitchProps<T extends string> {
  condition: T;
  children: ReactNode;
}

// Symbols for runtime identification
const CaseSymbol = Symbol('Switch.Case');
const DefaultSymbol = Symbol('Switch.Default');

// Case component
function CaseComponent<T extends string>({ children }: CaseProps<T>): ReactElement {
  return <>{children}</> as ReactElement;
}
(CaseComponent as any)[CaseSymbol] = true;

// Default component
function DefaultComponent({ children }: DefaultProps): ReactElement {
  return <>{children}</> as ReactElement;
}
(DefaultComponent as any)[DefaultSymbol] = true;

// Switch component
function SwitchComponent<T extends string>({
  condition,
  children,
}: SwitchProps<T>): ReactElement {
  let matchedChild: ReactNode | null = null;
  let defaultChild: ReactNode | null = null;

  React.Children.forEach(children, (child) => {
    if (React.isValidElement(child)) {
      if ((child.type as any)[CaseSymbol]) {
        const caseChild = child as React.ReactElement<CaseProps<T>>;
        if (caseChild.props.when === condition) {
          matchedChild = child;
        }
      } else if ((child.type as any)[DefaultSymbol]) {
        defaultChild = child;
      }
    }
  });

  return <>{matchedChild || defaultChild}</> as ReactElement;
}

// Helper function that creates a typed Switch with bound Case component
function createSwitch<T extends string>() {
  const TypedCase = (props: CaseProps<T>) => CaseComponent(props);
  (TypedCase as any)[CaseSymbol] = true;

  const TypedSwitch = (props: SwitchProps<T>) => SwitchComponent(props);

  return Object.assign(TypedSwitch, {
    Case: TypedCase,
    Default: DefaultComponent,
  });
}

// Generic Switch for general use
const Switch = Object.assign(SwitchComponent, {
  Case: CaseComponent,
  Default: DefaultComponent,
});

export default Switch;
export { createSwitch };