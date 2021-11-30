import { MenuItem } from "@blueprintjs/core";
import { IItemRendererProps, Omnibar } from "@blueprintjs/select";

export interface Location {
    type: string;
    address?: bigint;
    name?: string;
}

const renderCreateLocation = (query: string, active: boolean, handleClick: React.MouseEventHandler<HTMLElement>) => {
    try {
        BigInt(query);
        return (
            <MenuItem
                icon="add"
                text={`go to address: ${query}`}
                active={active}
                onClick={handleClick}
                shouldDismissPopover={true}
            />
        );
    } catch {
        return undefined;
    }
};

const renderLocationText = (item: Location): string => {
    let ret = item.type + ": ";

    if (item.address !== undefined && item.name !== undefined) {
        ret += item.name;
        ret += "@";
        ret += "0x" + item.address.toString(0x10);
    } else if (item.address !== undefined) {
        ret += "0x" + item.address.toString(0x10);
    } else if (item.name !== undefined) {
        ret += item.name;
    }

    return ret;
};

const renderLocation = (item: Location, { handleClick, modifiers }: IItemRendererProps) => (
    <MenuItem
        key={renderLocationText(item)}
        text={renderLocationText(item)}
        active={modifiers.active}
        onClick={handleClick}
        shouldDismissPopover={true}
    />
);

function createAddressLocationFromQuery(query: string) {
    try {
        return {
            type: "address",
            address: BigInt(query),
        };
    } catch {
        // when undefiend, the item is not created
        return undefined;
    }
}

export const LocationOmnibar = (props: { isOpen: boolean; locations: Location[]; onClose: any; onItemSelect: any }) => {
    const { isOpen, locations, onClose, onItemSelect } = props;
    const _LocationOmnibar = Omnibar.ofType<Location>();

    const predicate = (query: string, item: Location): boolean => {
        if (item.address !== undefined) {
            if (("0x" + item.address.toString(0x10)).includes(query.toLowerCase())) {
                return true;
            }
        }

        if (item.name !== undefined) {
            if (item.name.toLowerCase().includes(query.toLowerCase())) {
                return true;
            }
        }
        return false;
    };

    return (
        <_LocationOmnibar
            overlayProps={{ portalContainer: document.getElementById("app") as HTMLElement }}
            isOpen={isOpen}
            items={locations}
            itemPredicate={predicate}
            itemRenderer={renderLocation}
            createNewItemPosition="first"
            createNewItemRenderer={renderCreateLocation}
            createNewItemFromQuery={createAddressLocationFromQuery as any /* sorry */}
            onItemSelect={onItemSelect}
            onClose={onClose}
        />
    );
};
