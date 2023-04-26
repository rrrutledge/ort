/*
 * Copyright (C) 2017 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

package org.ossreviewtoolkit.model

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties

import java.time.Instant

import org.ossreviewtoolkit.model.config.ScannerConfiguration
import org.ossreviewtoolkit.model.utils.mergeScanResultsByScanner
import org.ossreviewtoolkit.utils.common.getDuplicates
import org.ossreviewtoolkit.utils.ort.Environment

/**
 * The summary of a single run of the scanner.
 */
@JsonIgnoreProperties(value = ["has_issues", "storage_stats"], allowGetters = true)
data class ScannerRun(
    /**
     * The [Instant] the scanner was started.
     */
    val startTime: Instant,

    /**
     * The [Instant] the scanner has finished.
     */
    val endTime: Instant,

    /**
     * The [Environment] in which the scanner was executed.
     */
    val environment: Environment,

    /**
     * The [ScannerConfiguration] used for this run.
     */
    val config: ScannerConfiguration,

    /**
     * The results of the provenance resolution for all projects and packages.
     */
    val provenances: List<ProvenanceResolutionResult>,

    /**
     * The scan results for each resolved provenance.
     */
    val scanResults: List<ScanResult>
) {
    companion object {
        /**
         * A constant for a [ScannerRun] where all properties are empty.
         */
        @JvmField
        val EMPTY = ScannerRun(
            startTime = Instant.EPOCH,
            endTime = Instant.EPOCH,
            environment = Environment(),
            config = ScannerConfiguration(),
            provenances = emptyList(),
            scanResults = emptyList()
        )
    }

    init {
        scanResults.forEach { scanResult ->
            require(scanResult.provenance is KnownProvenance) {
                "Found a scan result with an unknown provenance, which is not allowed."
            }

            (scanResult.provenance as? RepositoryProvenance)?.let { repositoryProvenance ->
                require(repositoryProvenance.vcsInfo.path.isEmpty()) {
                    "Found a scan result with a non-empty VCS path, which is not allowed."
                }

                require(repositoryProvenance.vcsInfo.revision == repositoryProvenance.resolvedRevision) {
                    "The revision and resolved revision of a scan result are not equal, which is not allowed."
                }
            }
        }

        provenances.getDuplicates { it.id }.keys.let { idsForDuplicateProvenanceResolutionResults ->
            require(idsForDuplicateProvenanceResolutionResults.isEmpty()) {
                "Found multiple provenance resolution results for the following ids: " +
                        "${idsForDuplicateProvenanceResolutionResults.joinToString { it.toCoordinates() }}."
            }
        }

        val scannedProvenances = scanResults.mapTo(mutableSetOf()) { it.provenance }
        val resolvedProvenances = provenances.flatMapTo(mutableSetOf()) {
            it.getKnownProvenancesWithoutVcsPath().values
        }

        (scannedProvenances - resolvedProvenances).let {
            require(it.isEmpty()) {
                "Found scan results which do not correspond to any resolved provenances, which is not allowed: " +
                    "${it.joinToString("\n") { it.toYaml() }}."
            }
        }
    }

    private val provenancesForId: Map<Identifier, ProvenanceResolutionResult> by lazy {
        provenances.associateBy { it.id }
    }

    private val scanResultsForProvenance: Map<KnownProvenance, List<ScanResult>> by lazy {
        scanResults.groupBy { it.provenance as KnownProvenance }
    }

    private val scanResultsForId: Map<Identifier, List<ScanResult>> by lazy {
        provenances.map { it.id }.associateWith { id -> getScanResultsForId(id) }
    }

    private fun getScanResultsForId(id: Identifier): List<ScanResult> {
        // 1. if package provenance was not resolved -> scan result with 1 issue
        // 2. else if there was at least one scan result, add nested resolution issue to all scan results
        // 3. else add a separate scan results for the nested provenance resolution issue.
        val resolutionResult = provenancesForId.getValue(id)

        resolutionResult.packageProvenanceResolutionIssue?.let {
            return listOf(scanResultForProvenanceResolutionIssue(resolutionResult.packageProvenance, it))
        }

        val packageProvenance = resolutionResult.packageProvenance!!

        val scanResultsByPath = resolutionResult.getKnownProvenancesWithoutVcsPath().mapValues { (_, provenance) ->
            scanResultsForProvenance[provenance].orEmpty()
        }

        val scanResults = mergeScanResultsByScanner(scanResultsByPath).map { scanResult ->
            scanResult.filterByPath(packageProvenance.vcsPath).filterByIgnorePatterns(config.ignorePatterns)
        }.map { scanResult ->
            // The VCS revision of scan result is equal to the resolved revision. So, use the package provenance
            // to re-align the VCS revision with the package's metadata.
            scanResult.copy(
                provenance = packageProvenance,
                summary = scanResult.summary.addIssue(resolutionResult.nestedProvenanceResolutionIssue)
            )
        }

        return scanResults.takeIf { it.isNotEmpty() }
            ?: resolutionResult.nestedProvenanceResolutionIssue?.let { issue ->
                listOf(scanResultForProvenanceResolutionIssue(packageProvenance, issue))
            }.orEmpty()
    }

    @JsonIgnore
    fun getAllScanResults(): Map<Identifier, List<ScanResult>> = scanResultsForId

    fun getScanResults(id: Identifier): List<ScanResult> = scanResultsForId[id].orEmpty()

    @JsonIgnore
    fun getIssues(): Map<Identifier, Set<Issue>> =
        scanResultsForId.mapValues { (_, scanResults) ->
            scanResults.flatMapTo(mutableSetOf()) { it.summary.issues }
        }
}

private fun ProvenanceResolutionResult.getKnownProvenancesWithoutVcsPath(): Map<String, KnownProvenance> =
    buildMap {
        when (packageProvenance) {
            is RepositoryProvenance -> put("", packageProvenance.clearVcsPath().alignRevisions())
            is ArtifactProvenance -> put("", packageProvenance)
            else -> { }
        }

        subRepositories.mapValuesTo(this) { (_, vcsInfo) ->
            RepositoryProvenance(vcsInfo = vcsInfo, resolvedRevision = vcsInfo.revision)
        }
    }

private val Provenance.vcsPath: String
    get() = (this as? RepositoryProvenance)?.vcsInfo?.path.orEmpty()

private fun RepositoryProvenance.clearVcsPath() = copy(vcsInfo = vcsInfo.copy(path = ""))

private fun RepositoryProvenance.alignRevisions(): RepositoryProvenance =
    copy(vcsInfo = vcsInfo.copy(revision = resolvedRevision))

private fun scanResultForProvenanceResolutionIssue(packageProvenance: KnownProvenance?, issue: Issue): ScanResult =
    ScanResult(
        packageProvenance ?: UnknownProvenance,
        scanner = ScannerDetails(name = "ProvenanceResolver", version = "", configuration = ""),
        summary = ScanSummary.EMPTY.copy(
            issues = listOf(issue)
        )
    )

private fun ScanSummary.addIssue(issue: Issue?): ScanSummary =
    if (issue == null) this else copy(issues = (issues + issue).distinct())
