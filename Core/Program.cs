// Copyright (c) Tunnel Vision Laboratories, LLC. All Rights Reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace StyleCop.Console
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Windows.Threading;
    using Microsoft.CodeAnalysis;
    using Microsoft.CodeAnalysis.CodeActions;
    using Microsoft.CodeAnalysis.CodeFixes;
    using Microsoft.CodeAnalysis.Diagnostics;
    using Microsoft.CodeAnalysis.MSBuild;
    using Microsoft.CodeAnalysis.Text;
    using StyleCop.Analyzers.Helpers;
    using File = System.IO.File;
    using Path = System.IO.Path;

    /// <summary>
    /// StyleCop.Console is simple tool for find diagnostics on solution,
    /// origially from StyleCop.Analyzers's StyleCopTester sample project
    /// </summary>
    internal static class Program
    {
        private static Assembly styleCopAnalyzersDll;
        private static Assembly styleCopAnalyzersCodeFixesDll;
        private static bool isVerbose;

        private static void Main(string[] args)
        {
            CancellationTokenSource cts = new CancellationTokenSource();
            Console.CancelKeyPress +=
                (sender, e) =>
                {
                    e.Cancel = true;
                    cts.Cancel();
                };

            // Since Console apps do not have a SynchronizationContext, we're leveraging the built-in support
            // in WPF to pump the messages via the Dispatcher.
            // See the following for additional details:
            //   http://blogs.msdn.com/b/pfxteam/archive/2012/01/21/10259307.aspx
            //   https://github.com/DotNetAnalyzers/StyleCopAnalyzers/pull/1362
            SynchronizationContext previousContext = SynchronizationContext.Current;
            try
            {
                var context = new DispatcherSynchronizationContext();
                SynchronizationContext.SetSynchronizationContext(context);

                DispatcherFrame dispatcherFrame = new DispatcherFrame();
                Task mainTask = MainAsync(args, cts.Token);
                mainTask.ContinueWith(task => dispatcherFrame.Continue = false);

                Dispatcher.PushFrame(dispatcherFrame);
                mainTask.GetAwaiter().GetResult();
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(previousContext);
            }
        }

        private static void PrintHelp()
        {
            WriteOutput("Usage: StyleCop.Console [options] <Solution>");
            WriteOutput("  Report stylecop diagnostics using StyleCop.Analysis");
            WriteOutput("  Options:");
            WriteOutput("    /fix:<id>    Write code fix of designated id (ex. /fix:SA1003)");
            WriteOutput("    /verbose /v  Output verbose log to console (A log starts with #)");
        }

        private static void LoadDefaultAssemblies()
        {
            string path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

            var styleCopAnalyzersDllFiles = Directory.GetFiles(path, "StyleCop.Analyzers.dll");
            var styleCopAnalyzersCodeFixesDllFile = Directory.GetFiles(path, "StyleCop.Analyzers.CodeFixes.dll");
            if (styleCopAnalyzersDllFiles.Count() != 1 || styleCopAnalyzersCodeFixesDllFile.Count() != 1)
            {
                WriteError("Error: Cannot read StyleCop.Analyzers dll files");
                return;
            }

            styleCopAnalyzersDll = Assembly.LoadFile(styleCopAnalyzersDllFiles.First());
            styleCopAnalyzersCodeFixesDll = Assembly.LoadFile(styleCopAnalyzersCodeFixesDllFile.First());
            if (styleCopAnalyzersDll == null || styleCopAnalyzersCodeFixesDll == null)
            {
                WriteError("Error: Cannot load StyleCop.Analyzers dlls");
                return;
            }
        }

        private static async Task<int> MainAsync(string[] args, CancellationToken cancellationToken)
        {
            // Load StyleCop.Analyzers related dll
            LoadDefaultAssemblies();

            // verbose option
            isVerbose = args.Contains("/verbose") || args.Contains("/v");

            // A valid call must have at least one parameter (a solution file).
            if (args.Where(a => a.StartsWith("/") == false).Count() < 1)
            {
                PrintHelp();
                return -1;
            }

            // open solution
            MSBuildWorkspace workspace = MSBuildWorkspace.Create();
            string solutionPath = args.SingleOrDefault(i => !i.StartsWith("/", StringComparison.Ordinal));
            Solution solution = await workspace.OpenSolutionAsync(solutionPath, cancellationToken).ConfigureAwait(false);

            string fixArg = args.FirstOrDefault(x => x.StartsWith("/fix:"));
            if (fixArg == null)
            {
                // TODO read ruleset file from arg

                // find and filter analyzers
                var analyzers = FilterAnalyzers(GetAllAnalyzers(), args).ToImmutableArray();
                if (analyzers.Length == 0)
                {
                    WriteError($"Error: Analyzers are empty");
                    return -1;
                }

                var diagnostics = await GetAnalyzerDiagnosticsAsync(solution, solutionPath, analyzers, cancellationToken).ConfigureAwait(true);

                // write diagnostics result to console if verbose option on
                if (isVerbose)
                {
                    var allDiagnostics = diagnostics.SelectMany(i => i.Value).ToImmutableArray();
                    foreach (var group in allDiagnostics.GroupBy(i => i.Id).OrderBy(i => i.Key, StringComparer.OrdinalIgnoreCase))
                    {
                        WriteOutput($"  {group.Key}: {group.Count()} instances");

                        // Print out analyzer diagnostics like AD0001 for analyzer exceptions
                        if (group.Key.StartsWith("AD", StringComparison.Ordinal))
                        {
                            foreach (var item in group)
                            {
                                WriteOutput(item.ToString());
                            }
                        }
                    }
                }

                WriteDiagnosticResults(diagnostics.SelectMany(i => i.Value.Select(j => Tuple.Create(i.Key, j))).ToImmutableArray());
            }
            else
            {
                string fixRuldId = fixArg.Substring(fixArg.IndexOf(':') + 1);

                // find analyzers
                var analyzers = GetAllAnalyzers().Where(a => a.SupportedDiagnostics.Any(s => s.Id == fixRuldId)).ToImmutableArray();
                if (analyzers.Length == 0)
                {
                    WriteError($"Error: Cannot find Analyzers for {fixRuldId}");
                    return -1;
                }

                var diagnostics = await GetAnalyzerDiagnosticsAsync(solution, solutionPath, analyzers, cancellationToken).ConfigureAwait(true);
                await TestFixAllAsync(solution, diagnostics, true, cancellationToken).ConfigureAwait(true);
            }

            return 0;
        }

        private static void WriteDiagnosticResults(ImmutableArray<Tuple<ProjectId, Diagnostic>> diagnostics)
        {
            var orderedDiagnostics =
                diagnostics
                .OrderBy(i => i.Item2.Id)
                .ThenBy(i => i.Item2.Location.SourceTree?.FilePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(i => i.Item2.Location.SourceSpan.Start)
                .ThenBy(i => i.Item2.Location.SourceSpan.End);

            StringBuilder completeOutput = new StringBuilder();
            foreach (var diagnostic in orderedDiagnostics)
            {
                WriteOutput(diagnostic.Item2.ToString());
            }
        }

        private static async Task TestFixAllAsync(Solution solution, ImmutableDictionary<ProjectId, ImmutableArray<Diagnostic>> diagnostics, bool applyChanges, CancellationToken cancellationToken)
        {
            var codeFixers = GetAllCodeFixers().SelectMany(x => x.Value).Distinct();

            var equivalenceGroups = new List<CodeFixEquivalenceGroup>();
            foreach (var codeFixer in codeFixers)
            {
                equivalenceGroups.AddRange(await CodeFixEquivalenceGroup.CreateAsync(codeFixer, diagnostics, solution, cancellationToken).ConfigureAwait(true));
            }

            WriteOutput($"Found {equivalenceGroups.Count} equivalence groups.");
            if (applyChanges && equivalenceGroups.Count > 1)
            {
                WriteError("/fix can only be used with a single equivalence group.");
                return;
            }

            foreach (var fix in equivalenceGroups)
            {
                var stopwatch = new Stopwatch();

                try
                {
                    stopwatch.Restart();

                    WriteOutput($"Calculating fix for {fix.CodeFixEquivalenceKey} using {fix.FixAllProvider} for {fix.NumberOfDiagnostics} instances.");
                    var operations = await fix.GetOperationsAsync(cancellationToken).ConfigureAwait(true);
                    if (applyChanges)
                    {
                        var applyOperations = operations.OfType<ApplyChangesOperation>().ToList();
                        if (applyOperations.Count > 1)
                        {
                            WriteError("/fix can only apply a single code action operation.");
                        }
                        else if (applyOperations.Count == 0)
                        {
                            WriteOutput("No changes were found to apply.");
                        }
                        else
                        {
                            applyOperations[0].Apply(solution.Workspace, cancellationToken);
                        }
                    }

                    WriteOutput($"Calculating changes completed in {stopwatch.ElapsedMilliseconds}ms. This is {fix.NumberOfDiagnostics / stopwatch.Elapsed.TotalSeconds:0.000} instances/second.", ConsoleColor.Yellow);
                }
                catch (Exception ex)
                {
                    // Report thrown exceptions
                    WriteError($"The fix '{fix.CodeFixEquivalenceKey}' threw an exception after {stopwatch.ElapsedMilliseconds}ms:", ConsoleColor.Yellow);
                    WriteError(ex.ToString(), ConsoleColor.Yellow);
                }
            }
        }

        private static async Task<IEnumerable<CodeAction>> GetFixesAsync(Solution solution, CodeFixProvider codeFixProvider, Diagnostic diagnostic, CancellationToken cancellationToken)
        {
            List<CodeAction> codeActions = new List<CodeAction>();

            await codeFixProvider.RegisterCodeFixesAsync(new CodeFixContext(solution.GetDocument(diagnostic.Location.SourceTree), diagnostic, (a, d) => codeActions.Add(a), cancellationToken)).ConfigureAwait(false);

            return codeActions;
        }

        private static IEnumerable<DiagnosticAnalyzer> FilterAnalyzers(IEnumerable<DiagnosticAnalyzer> analyzers, string[] args)
        {
            foreach (var analyzer in analyzers)
            {
                if (analyzer.SupportedDiagnostics.Any(i => i.IsEnabledByDefault))
                {
                    yield return analyzer;
                }
            }
        }

        private static ImmutableArray<DiagnosticAnalyzer> GetAllAnalyzers()
        {
            Assembly assembly = styleCopAnalyzersDll;

            var diagnosticAnalyzerType = typeof(DiagnosticAnalyzer);
            var analyzers = ImmutableArray.CreateBuilder<DiagnosticAnalyzer>();

            foreach (var type in assembly.GetTypes())
            {
                if (type.IsSubclassOf(diagnosticAnalyzerType) && !type.IsAbstract)
                {
                    analyzers.Add((DiagnosticAnalyzer)Activator.CreateInstance(type));
                }
            }

            return analyzers.ToImmutable();
        }

        private static ImmutableDictionary<string, ImmutableList<CodeFixProvider>> GetAllCodeFixers()
        {
            Assembly assembly = styleCopAnalyzersCodeFixesDll;

            var codeFixProviderType = typeof(CodeFixProvider);
            Dictionary<string, ImmutableList<CodeFixProvider>> providers = new Dictionary<string, ImmutableList<CodeFixProvider>>();

            foreach (var type in assembly.GetTypes())
            {
                if (type.IsSubclassOf(codeFixProviderType) && !type.IsAbstract)
                {
                    var codeFixProvider = (CodeFixProvider)Activator.CreateInstance(type);
                    foreach (var diagnosticId in codeFixProvider.FixableDiagnosticIds)
                    {
                        providers.AddToInnerList(diagnosticId, codeFixProvider);
                    }
                }
            }

            return providers.ToImmutableDictionary();
        }

        private static ImmutableDictionary<FixAllProvider, ImmutableHashSet<string>> GetAllFixAllProviders(IEnumerable<CodeFixProvider> providers)
        {
            Dictionary<FixAllProvider, ImmutableHashSet<string>> fixAllProviders = new Dictionary<FixAllProvider, ImmutableHashSet<string>>();

            foreach (var provider in providers)
            {
                var fixAllProvider = provider.GetFixAllProvider();
                var supportedDiagnosticIds = fixAllProvider.GetSupportedFixAllDiagnosticIds(provider);
                foreach (var id in supportedDiagnosticIds)
                {
                    fixAllProviders.AddToInnerSet(fixAllProvider, id);
                }
            }

            return fixAllProviders.ToImmutableDictionary();
        }

        private static async Task<ImmutableDictionary<ProjectId, ImmutableArray<Diagnostic>>> GetAnalyzerDiagnosticsAsync(Solution solution, string solutionPath, ImmutableArray<DiagnosticAnalyzer> analyzers, CancellationToken cancellationToken)
        {
            List<KeyValuePair<ProjectId, Task<ImmutableArray<Diagnostic>>>> projectDiagnosticTasks = new List<KeyValuePair<ProjectId, Task<ImmutableArray<Diagnostic>>>>();

            // Make sure we analyze the projects in parallel
            foreach (var project in solution.Projects)
            {
                if (project.Language != LanguageNames.CSharp)
                {
                    continue;
                }

                projectDiagnosticTasks.Add(new KeyValuePair<ProjectId, Task<ImmutableArray<Diagnostic>>>(project.Id, GetProjectAnalyzerDiagnosticsAsync(analyzers, project, cancellationToken)));
            }

            ImmutableDictionary<ProjectId, ImmutableArray<Diagnostic>>.Builder projectDiagnosticBuilder = ImmutableDictionary.CreateBuilder<ProjectId, ImmutableArray<Diagnostic>>();
            foreach (var task in projectDiagnosticTasks)
            {
                projectDiagnosticBuilder.Add(task.Key, await task.Value.ConfigureAwait(false));
            }

            return projectDiagnosticBuilder.ToImmutable();
        }

        /// <summary>
        /// Returns a list of all analyzer diagnostics inside the specific project. This is an asynchronous operation.
        /// </summary>
        /// <param name="analyzers">The list of analyzers that should be used</param>
        /// <param name="project">The project that should be analyzed</param>
        /// <see langword="false"/> to use the behavior configured for the specified <paramref name="project"/>.</param>
        /// <param name="cancellationToken">The cancellation token that the task will observe.</param>
        /// <returns>A list of diagnostics inside the project</returns>
        private static async Task<ImmutableArray<Diagnostic>> GetProjectAnalyzerDiagnosticsAsync(ImmutableArray<DiagnosticAnalyzer> analyzers, Project project, CancellationToken cancellationToken)
        {
            var supportedDiagnosticsSpecificOptions = new Dictionary<string, ReportDiagnostic>();

            // DEBUG bgree
            supportedDiagnosticsSpecificOptions["SA1600"] = ReportDiagnostic.Suppress;
            supportedDiagnosticsSpecificOptions["SA1516"] = ReportDiagnostic.Suppress;
            supportedDiagnosticsSpecificOptions["SA1515"] = ReportDiagnostic.Suppress;

            // Report exceptions during the analysis process as errors
            supportedDiagnosticsSpecificOptions.Add("AD0001", ReportDiagnostic.Error);

            // update the project compilation options
            var modifiedSpecificDiagnosticOptions = supportedDiagnosticsSpecificOptions.ToImmutableDictionary().SetItems(project.CompilationOptions.SpecificDiagnosticOptions);
            var modifiedCompilationOptions = project.CompilationOptions.WithSpecificDiagnosticOptions(modifiedSpecificDiagnosticOptions);
            var processedProject = project.WithCompilationOptions(modifiedCompilationOptions);

            Compilation compilation = await processedProject.GetCompilationAsync(cancellationToken).ConfigureAwait(false);
            CompilationWithAnalyzers compilationWithAnalyzers = compilation.WithAnalyzers(analyzers, new CompilationWithAnalyzersOptions(new AnalyzerOptions(ImmutableArray.Create<AdditionalText>()), null, true, false));

            var diagnostics = await FixAllContextHelper.GetAllDiagnosticsAsync(compilation, compilationWithAnalyzers, analyzers, project.Documents, true, cancellationToken).ConfigureAwait(false);

            // DEBUG bgree filter on diagnostics
            diagnostics = diagnostics.Where(d => !d.Location.SourceTree.FilePath.Contains("ExternalLib")).ToImmutableArray();

            return diagnostics;
        }

        private static void WriteOutput(string text, ConsoleColor? color = null)
        {
            if (color != null)
            {
                Console.ForegroundColor = color.Value;
            }

            Console.WriteLine(text);

            if (color != null)
            {
                Console.ResetColor();
            }
        }

        private static void WriteError(string text, ConsoleColor? color = null)
        {
            if (color != null)
            {
                Console.ForegroundColor = color.Value;
            }

            Console.Error.WriteLine(text);

            if (color != null)
            {
                Console.ResetColor();
            }
        }
    }
}
