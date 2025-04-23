import React from "react";
import { Routes, Route } from "react-router-dom";

const Component = () => "tenent 01";

export default () => {
  return (
    <Routes>
      <Route path="*" element={<Component />} />
    </Routes>
  );
};
