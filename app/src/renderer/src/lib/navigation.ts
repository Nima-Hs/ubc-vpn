import { create } from "zustand";

interface Navigation {
    /** The screen being shown. */
    current: string;
    /** Whether the screen being shown has changes that leaving would lose. */
    unsaved: boolean;
    /** The screen the user asked for while there were unsaved changes. */
    wanted: string | null;
}

/**
 * Which screen is showing, and the one rule about leaving it: a screen with
 * unsaved changes is not left until the user has said what to do with them.
 */
export const useNavigation = create<Navigation>(() => ({
    current: "connection",
    unsaved: false,
    wanted: null,
}));

/** Goes to a screen, or, with unsaved changes, asks first. */
export function show(id: string): void {
    const { current, unsaved } = useNavigation.getState();
    if (id === current) {
        return;
    }
    useNavigation.setState(unsaved ? { wanted: id } : { current: id, wanted: null });
}

/** A screen says whether it has changes that would be lost. */
export function setUnsaved(unsaved: boolean): void {
    useNavigation.setState({ unsaved });
}

/** The user chose to stay. */
export function stay(): void {
    useNavigation.setState({ wanted: null });
}

/** The user chose to leave, and lose the changes. */
export function leave(): void {
    const { wanted, current } = useNavigation.getState();
    useNavigation.setState({ current: wanted ?? current, wanted: null, unsaved: false });
}
