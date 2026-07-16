import * as React from "react";
import { Check, ChevronsUpDown, Plus, X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";

export interface MultiSelectOption {
  value: string;
  label?: string;
  hint?: string;
}

export interface MultiSelectFieldProps {
  values: string[];
  onChange: (values: string[]) => void;
  options: Array<MultiSelectOption | string>;
  placeholder?: string;
  emptyText?: string;
  allowCustom?: boolean;
  disabled?: boolean;
  className?: string;
  renderIcon?: (value: string) => React.ReactNode;
  "aria-label"?: string;
}

export function MultiSelectField({
  values,
  onChange,
  options,
  placeholder = "Any (no restriction)",
  emptyText = "No matches",
  allowCustom = true,
  disabled = false,
  className,
  renderIcon,
  ...rest
}: MultiSelectFieldProps) {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const normalizedOptions = React.useMemo(() => options.map(asOption), [options]);
  const labels = React.useMemo(() => new Map(normalizedOptions.map((option) => [option.value, option.label || option.value])), [normalizedOptions]);

  const toggle = (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return;
    onChange(values.includes(trimmed) ? values.filter((item) => item !== trimmed) : [...values, trimmed]);
  };

  const filtered = normalizedOptions.filter((option) => {
    const needle = query.trim().toLowerCase();
    return `${option.value} ${option.label || ""}`.toLowerCase().includes(needle);
  });
  const customValue = query.trim();
  const canAddCustom = allowCustom && customValue.length > 0 && !normalizedOptions.some(
    (option) => option.value.toLowerCase() === customValue.toLowerCase()
  ) && !values.some((value) => value.toLowerCase() === customValue.toLowerCase());

  return (
    <div className={cn("space-y-2", className)}>
      {values.length ? (
        <div className="flex flex-wrap gap-1" aria-label="Selected values">
          {values.map((value) => (
            <Badge key={value} variant="secondary" className="gap-1 pr-1">
              {renderIcon ? <span className="flex items-center">{renderIcon(value)}</span> : null}
              {labels.get(value) || value}
              <button
                type="button"
                className="rounded-sm p-0.5 hover:bg-muted-foreground/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                aria-label={`Remove ${labels.get(value) || value}`}
                disabled={disabled}
                onClick={() => onChange(values.filter((item) => item !== value))}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      ) : null}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            type="button"
            variant="outline"
            role="combobox"
            aria-expanded={open}
            disabled={disabled}
            className="w-full justify-between font-normal"
            {...rest}
          >
            <span className={cn("truncate text-left", values.length === 0 && "text-muted-foreground")}>
              {values.length ? "Add or remove values" : placeholder}
            </span>
            <ChevronsUpDown className="h-4 w-4 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[var(--radix-popover-trigger-width)] min-w-56 p-0" align="start">
          <Command shouldFilter={false}>
            <CommandInput placeholder="Search or type a value..." value={query} onValueChange={setQuery} />
            <CommandList>
              {filtered.length === 0 && !canAddCustom ? <CommandEmpty>{emptyText}</CommandEmpty> : null}
              {canAddCustom ? (
                <CommandGroup>
                  <CommandItem
                    value={`add-${customValue}`}
                    onSelect={() => {
                      toggle(customValue);
                      setQuery("");
                    }}
                  >
                    <Plus className="h-4 w-4" />
                    Add &ldquo;{customValue}&rdquo;
                  </CommandItem>
                </CommandGroup>
              ) : null}
              {filtered.length ? (
                <CommandGroup>
                  {filtered.map((option) => {
                    const selected = values.includes(option.value);
                    return (
                      <CommandItem key={option.value} value={option.value} onSelect={() => toggle(option.value)}>
                        <Check className={cn("h-4 w-4", selected ? "opacity-100" : "opacity-0")} />
                        {renderIcon ? <span className="flex items-center">{renderIcon(option.value)}</span> : null}
                        <span className="flex-1 truncate">{option.label || option.value}</span>
                        {option.hint ? <span className="text-xs text-muted-foreground">{option.hint}</span> : null}
                      </CommandItem>
                    );
                  })}
                </CommandGroup>
              ) : null}
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
    </div>
  );
}

function asOption(option: MultiSelectOption | string): MultiSelectOption {
  return typeof option === "string" ? { value: option } : option;
}
