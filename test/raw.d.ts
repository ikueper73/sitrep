// Vite's ?raw imports, used for XML fixtures. Kept in a file without imports so it is global.
declare module "*.xml?raw" {
  const content: string;
  export default content;
}
