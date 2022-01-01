import { Dispatch } from "@reduxjs/toolkit";
import { configureStore, createSlice } from "@reduxjs/toolkit";

export interface AppState {
    address: BigInt;
    address_history: BigInt[];
}

export const { actions, reducer } = createSlice({
    name: "app",
    initialState: {
        address: BigInt(0x0),
        address_history: [],
    },
    reducers: {
        set_address: (state: AppState, action) => {
            // TODO: can't store BigInts in the store
            state.address = action.payload;
            state.address_history.push(action.payload);
        },
        pop_history: (state: AppState) => {
            if (state.address_history.length > 0) {
                state.address = state.address_history[state.address_history.length - 1];
                state.address_history.pop();
            }
        },
    },
});

export const store = configureStore({
    reducer,
});

export interface Dispatches {
    dispatch: Dispatch<any>;
}
