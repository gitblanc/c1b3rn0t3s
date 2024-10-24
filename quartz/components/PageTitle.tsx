import { joinSegments, pathToRoot } from "../util/path"
import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import { classNames } from "../util/lang"
import { i18n } from "../i18n"

// const PageTitle: QuartzComponent = ({ fileData, cfg, displayClass }: QuartzComponentProps) => {
//   const title = cfg?.pageTitle ?? i18n(cfg.locale).propertyDefaults.title
//   const baseDir = pathToRoot(fileData.slug!)
//   return (
//     <h1 class={classNames(displayClass, "page-title")}>
//       <a href={baseDir}>{title}</a>
//     </h1>
//   )
// }

const PageTitle: QuartzComponent = ({ fileData, cfg, displayClass }: QuartzComponentProps) => {
  const title = cfg?.pageTitle ?? i18n(cfg.locale).propertyDefaults.title
  const baseDir = pathToRoot(fileData.slug!)
  const iconPath = joinSegments(baseDir, "static/logo.png")
  return (
    <h2 class={classNames(displayClass, "page-title")}>
      <a href={baseDir}>
        <img class="Logo" src={iconPath} alt={title}/>
      </a>
    </h2>
  )
}

// PageTitle.css = `
// .page-title {
//   margin: 0;
// }
// `

PageTitle.css = `
.page-title {
  font-size: 1.75rem;
  margin: 0;
}
.Logo {
  height: 80%;
  width: 80%;
  margin: 0;
}
`

// PageTitle.css = `
// .page-title {
//   font-size: 1.75rem;
//   margin: 0;
// }
// `

export default (() => PageTitle) satisfies QuartzComponentConstructor
